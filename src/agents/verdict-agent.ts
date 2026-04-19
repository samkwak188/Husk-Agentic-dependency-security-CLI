import { POPULAR_PACKAGES } from "../subsystems/typosquat/popular-packages.js";
import { classifyNetworkActivity } from "../subsystems/sandbox/network-classifier.js";
import type {
  BehaviorDiff,
  DeobfuscationResult,
  HuskVerdict,
  IOCMatch,
  PackageMetadata,
  PackageShapeResult,
  SandboxResult,
  TyposquatResult,
  VerdictReason
} from "../core/types.js";

interface VerdictInputs {
  metadata: PackageMetadata;
  iocs: IOCMatch[];
  behaviorDiff?: BehaviorDiff;
  deobfuscation?: DeobfuscationResult;
  sandboxResult?: SandboxResult;
  typosquat?: TyposquatResult | null;
  packageShape?: PackageShapeResult;
}

type SignalCategory =
  | "ioc-credential"
  | "ioc-network"
  | "ioc-process"
  | "ioc-other"
  | "deobf-urls"
  | "deobf-score"
  | "deobf-sinks"
  | "sandbox-network"
  | "sandbox-credential"
  | "sandbox-workflow"
  | "behavior-diff"
  | "typosquat"
  | "package-shape";

function classifyIocCategory(match: IOCMatch): SignalCategory {
  const text = `${match.description} ${match.evidence}`.toLowerCase();
  if (/credential|secret|token|password|env|\.npmrc|netrc|aws|github_token/.test(text)) return "ioc-credential";
  if (/network|http|fetch|axios|request|exfil|webhook|discord|telegram/.test(text)) return "ioc-network";
  if (/spawn|exec|child_process|powershell|bash|shell|process/.test(text)) return "ioc-process";
  return "ioc-other";
}

const POPULAR_PACKAGE_SET = new Set(POPULAR_PACKAGES.map((name) => name.toLowerCase()));

function severityWeight(severity: IOCMatch["severity"]): number {
  switch (severity) {
    case "CRITICAL":
      return 40;
    case "HIGH":
      return 20;
    case "MEDIUM":
      return 10;
    default:
      return 3;
  }
}

export class VerdictAgent {
  decide(input: VerdictInputs): HuskVerdict {
    const reasons: VerdictReason[] = [];
    const triggeredCategories = new Set<SignalCategory>();
    let highestSeverity: IOCMatch["severity"] = "LOW";
    let score = 0;

    const noteSeverity = (severity: IOCMatch["severity"]) => {
      const ranking = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as const;
      if (ranking[severity] > ranking[highestSeverity]) {
        highestSeverity = severity;
      }
    };

    for (const match of input.iocs) {
      const scoreImpact = severityWeight(match.severity);
      score += scoreImpact;
      triggeredCategories.add(classifyIocCategory(match));
      noteSeverity(match.severity);
      reasons.push({
        severity: match.severity,
        scoreImpact,
        title: "IOC match",
        evidence: `${match.description} (${match.evidence})`
      });
    }

    if (input.sandboxResult) {
      const network = classifyNetworkActivity(input.sandboxResult.networkAttempts);
      if (network.suspicious.length) {
        const networkImpact = network.suspicious.length >= 3 ? 25 : 12;
        score += networkImpact;
        triggeredCategories.add("sandbox-network");
        noteSeverity("HIGH");
        reasons.push({
          severity: "HIGH",
          scoreImpact: networkImpact,
          title: "Outbound network activity to non-registry destinations",
          evidence: `${network.suspicious.length} suspicious connection${network.suspicious.length === 1 ? "" : "s"} to ${network.uniqueSuspiciousDestinations} destination${network.uniqueSuspiciousDestinations === 1 ? "" : "s"} (${network.destinationsPreview})`
        });
      }

      const credentialFinding = input.sandboxResult.findings.find(
        (finding) => finding.ruleId.startsWith("credential-write") || finding.ruleId === "secret-harvest"
      );
      if (credentialFinding) {
        score += 35;
        triggeredCategories.add("sandbox-credential");
        noteSeverity(credentialFinding.severity);
        reasons.push({
          severity: credentialFinding.severity,
          scoreImpact: 35,
          title: "Credential access or overwrite",
          evidence: credentialFinding.evidence
        });
      }

      const workflowFinding = input.sandboxResult.findings.find((finding) => finding.ruleId === "workflow-write");
      if (workflowFinding) {
        score += 40;
        triggeredCategories.add("sandbox-workflow");
        noteSeverity(workflowFinding.severity);
        reasons.push({
          severity: workflowFinding.severity,
          scoreImpact: 40,
          title: "Workflow propagation behavior",
          evidence: workflowFinding.evidence
        });
      }
    }

    if (input.deobfuscation) {
      const sinkCount = input.deobfuscation.revealedSinks?.length ?? 0;
      const urlCount = input.deobfuscation.revealedUrls.length;
      const stringCount = input.deobfuscation.revealedStrings?.length ?? 0;
      const sourceFile = input.deobfuscation.sourceFile ?? "(unknown file)";

      // Real obfuscation has THREE simultaneous markers:
      //   1. high suspicion score
      //   2. concrete sinks or outbound URLs (something to be hidden)
      //   3. resolved strings — the deobfuscator's string-array / eval-unwrap
      //      / base64-decode visitors actually unmasked encoded content
      //
      // mongodb's connection_string.ts and typescript's lib/_tsserver.js
      // both score 100/100 with many sinks but ZERO resolved strings —
      // they're just dense legitimate code, not obfuscated. Requiring
      // resolvedStrings > 5 distinguishes "looks suspicious" from "actively
      // hiding something".
      //
      // Exception: even one unmasked HARD sink (exec / spawn / eval / Function)
      // is conclusive. Small obfuscated payloads that decode to a single
      // `child_process.exec(...)` would otherwise slip through the > 5
      // resolved-strings threshold (e.g. our evil-obfuscated test fixture).
      const HARD_SINKS = ["exec", "execSync", "spawn", "spawnSync", "eval", "Function", "require:child_process", "import:child_process"];
      const hasHardSink = (input.deobfuscation.revealedSinks ?? []).some((s) => HARD_SINKS.includes(s));
      const fireObfuscation =
        input.deobfuscation.suspicionScore > 65 &&
        ((stringCount > 5 && (sinkCount > 0 || urlCount > 0)) || hasHardSink);
      if (fireObfuscation) {
        score += 20;
        triggeredCategories.add("deobf-score");
        noteSeverity("HIGH");
        reasons.push({
          severity: "HIGH",
          scoreImpact: 20,
          title: "Heavy obfuscation with unmasked sinks",
          evidence: `Obfuscation score ${input.deobfuscation.suspicionScore}/100 in ${sourceFile} — deobfuscator unmasked ${stringCount} encoded strings revealing ${sinkCount} sink${sinkCount === 1 ? "" : "s"} and ${urlCount} URL${urlCount === 1 ? "" : "s"}`
        });
      }

      if (urlCount > 0) {
        score += 35;
        triggeredCategories.add("deobf-urls");
        noteSeverity("HIGH");
        const sample = input.deobfuscation.revealedUrls.slice(0, 3).join(", ");
        const more = urlCount > 3 ? ` (+${urlCount - 3} more)` : "";
        reasons.push({
          severity: "HIGH",
          scoreImpact: 35,
          title: "Outbound URL passed to a network call",
          evidence: `${urlCount} URL${urlCount === 1 ? "" : "s"} reached a fetch/http/axios call site in ${sourceFile}: ${sample}${more}`
        });
      }

      if (sinkCount > 0) {
        score += 15;
        triggeredCategories.add("deobf-sinks");
        noteSeverity("MEDIUM");
        const sample = input.deobfuscation.revealedSinks.slice(0, 5).join(", ");
        reasons.push({
          severity: "MEDIUM",
          scoreImpact: 15,
          title: "Dangerous sinks resolved during deobfuscation",
          evidence: `${sinkCount} sink${sinkCount === 1 ? "" : "s"} unmasked in ${sourceFile}: ${sample}`
        });
      }

      // Co-occurrence on resolved strings: catches the obfuscation pattern
      // where the AST sink scorer can't see the call site (e.g. computed
      // properties like `obj['exec'](...)` after string-array decoding) but
      // the deobfuscator clearly unmasked the constituent strings. If
      // BOTH a dangerous module name AND a dangerous method name appear
      // among unmasked strings, that's intentional obfuscation of a
      // dangerous sink — fire HIGH regardless of suspicion score.
      const stringsLower = (input.deobfuscation.revealedStrings ?? []).map((s) => String(s).toLowerCase());
      const HIDDEN_MODULES = new Set(["child_process", "fs", "http", "https", "net", "dns", "vm"]);
      const HIDDEN_METHODS = new Set(["exec", "execsync", "spawn", "spawnsync", "eval", "function"]);
      const moduleHits = stringsLower.filter((s) => HIDDEN_MODULES.has(s));
      const methodHits = stringsLower.filter((s) => HIDDEN_METHODS.has(s));
      if (moduleHits.length > 0 && methodHits.length > 0) {
        score += 25;
        triggeredCategories.add("deobf-sinks");
        noteSeverity("HIGH");
        reasons.push({
          severity: "HIGH",
          scoreImpact: 25,
          title: "Obfuscated dangerous-API references unmasked",
          evidence: `Deobfuscator unmasked '${moduleHits.join(", ")}' and '${methodHits.join(", ")}' as separate string fragments in ${sourceFile} — these were intentionally split to bypass static analysis`
        });
      }
    }

    if (input.behaviorDiff) {
      const newNetworkCapabilities = input.behaviorDiff.newCapabilities.filter((capability) => capability.type === "network");
      if (newNetworkCapabilities.length) {
        score += 15;
        triggeredCategories.add("behavior-diff");
        noteSeverity("MEDIUM");
        reasons.push({
          severity: "MEDIUM",
          scoreImpact: 15,
          title: "New network capability introduced",
          evidence: newNetworkCapabilities.map((capability) => capability.detail).join(", ")
        });
      }

      if (input.behaviorDiff.installScriptChanged) {
        score += 10;
        triggeredCategories.add("behavior-diff");
        noteSeverity("MEDIUM");
        reasons.push({
          severity: "MEDIUM",
          scoreImpact: 10,
          title: "Install script changed from previous version",
          evidence: input.behaviorDiff.installScriptDiff ?? "install lifecycle modified"
        });
      }
    }

    if (input.typosquat) {
      const impact = input.typosquat.distance <= 1 ? 20 : 10;
      score += impact;
      triggeredCategories.add("typosquat");
      noteSeverity("MEDIUM");
      reasons.push({
        severity: "MEDIUM",
        scoreImpact: impact,
        title: "Typosquat signal",
        evidence: `${input.metadata.name} resembles ${input.typosquat.target}`
      });
    }

    // Package-shape signal: catches empty / dependency-confusion stubs
    // that have no code for any other detector to find. Calibrated in two
    // tiers:
    //
    //   1. Empty source + name carries attack signals (keywords like "poc"
    //      / "exploit", numeric-prefix pattern, pristine-stub keywords) →
    //      HIGH severity, score impact 40. This is the dependency-confusion
    //      drop signature. By definition no other detector can fire because
    //      there is no code to inspect, so the score has to be high enough
    //      on its own to flip SUSPICIOUS via the single-HIGH path.
    //
    //   2. Empty source + no README, no name signals → MEDIUM severity,
    //      score impact 15. Worth surfacing as a co-signal but not a
    //      stand-alone alert. Lots of legit utility packages look like
    //      this (single-purpose helpers without a README), so we wait for
    //      another detector to corroborate.
    if (input.packageShape && input.packageShape.signal === "suspicious") {
      const hasNameSignals = input.packageShape.suspiciousNameSignals.length > 0;
      const isVeryEmpty = input.packageShape.totalSourceBytes < 200;
      const isAttackPattern = hasNameSignals && isVeryEmpty;

      const severity: VerdictReason["severity"] = isAttackPattern ? "HIGH" : "MEDIUM";
      const impact = isAttackPattern ? 40 : 15;
      score += impact;
      triggeredCategories.add("package-shape");
      noteSeverity(severity);
      reasons.push({
        severity,
        scoreImpact: impact,
        title: isAttackPattern
          ? "Empty package with dependency-confusion name pattern"
          : "Unusually empty package — review before installing",
        evidence: input.packageShape.reason
      });
    }

    const correlation = this.applyCorrelation({
      score,
      categories: triggeredCategories,
      highestSeverity,
      packageName: input.metadata.name
    });

    const recommendations = this.buildRecommendations(input, correlation.verdict);

    return {
      verdict: correlation.verdict,
      ecosystem: input.metadata.ecosystem,
      confidence: correlation.confidence,
      reasons: this.sortReasons(reasons),
      recommendations,
      policy: {
        action: "ALLOW",
        summary: "No policy evaluation has been applied yet.",
        reasons: ["Policy evaluation pending."],
        policyName: "uninitialized",
        canOverride: false,
        reviewRequired: false
      },
      iocs: input.iocs,
      behaviorDiff: input.behaviorDiff,
      deobfuscation: input.deobfuscation,
      sandboxResult: input.sandboxResult,
      typosquat: input.typosquat ?? null,
      packageShape: input.packageShape,
      scanDuration: 0,
      timestamp: new Date().toISOString(),
      workflow: {
        provider: "deterministic",
        apiEnabled: false,
        triage: { mode: "deterministic" },
        dynamicNarration: { mode: "deterministic" },
        reporting: { mode: "deterministic" }
      },
      packageName: input.metadata.name,
      packageVersion: input.metadata.version
    };
  }

  /**
   * Multi-signal correlation per arXiv 2603.27549: a single API call carries no directional
   * intent; a behavioral chain (≥2 distinct signal categories, or a single CRITICAL chain)
   * disambiguates malicious purpose. Popular packages get a stricter threshold (PyGuard / OSCAR):
   * canonical names with verified maintainers should require overwhelming evidence to flag,
   * because false positives on packages like express/lodash are far more damaging than letting
   * a borderline signal pass on a known-good package.
   */
  private applyCorrelation(args: {
    score: number;
    categories: Set<SignalCategory>;
    highestSeverity: IOCMatch["severity"];
    packageName: string;
  }): { verdict: HuskVerdict["verdict"]; confidence: number } {
    const { score, categories, highestSeverity, packageName } = args;
    const isPopular = POPULAR_PACKAGE_SET.has(packageName.toLowerCase());
    const distinctCategories = categories.size;
    const boundedScore = Math.min(100, score);

    let verdict: HuskVerdict["verdict"];

    if (isPopular) {
      // Popular packages get the benefit of the doubt: a single signal can
      // still raise SUSPICIOUS (so the user is told what fired) but only
      // overwhelming evidence flips to MALICIOUS — false positives on
      // express/lodash/react are far more damaging than slipping a borderline
      // signal past on a known-good package.
      const overwhelming = highestSeverity === "CRITICAL" || (distinctCategories >= 3 && boundedScore >= 70);
      const concerning =
        (distinctCategories >= 2 && boundedScore >= 35) ||
        highestSeverity === "HIGH";
      verdict = overwhelming ? "MALICIOUS" : concerning ? "SUSPICIOUS" : "CLEAN";
    } else {
      // For unknown packages we err on the side of catching attacks. This
      // closes the recall gap exposed by the benchmark: previously a single
      // HIGH-severity finding ("dangerous sinks", "IOC match") on a malicious
      // package was suppressed as "single low-confidence signal" and the
      // package was marked CLEAN. Now:
      //   - CRITICAL alone        → MALICIOUS
      //   - HIGH + any other      → MALICIOUS
      //   - HIGH alone            → SUSPICIOUS
      //   - MEDIUM + another      → SUSPICIOUS
      //   - score >= 35           → SUSPICIOUS
      const malicious =
        highestSeverity === "CRITICAL" ||
        (highestSeverity === "HIGH" && distinctCategories >= 2) ||
        (boundedScore >= 60 && distinctCategories >= 2);
      const suspicious =
        highestSeverity === "HIGH" ||
        (highestSeverity === "MEDIUM" && distinctCategories >= 2) ||
        boundedScore >= 35;
      verdict = malicious ? "MALICIOUS" : suspicious ? "SUSPICIOUS" : "CLEAN";
    }

    // Confidence calibration. Previously CLEAN was hard-coded to 0.85
    // regardless of evidence — which meant an unknown package with zero
    // detectors firing was reported as 85% confident SAFE TO INSTALL. That
    // is structural over-claiming. The honest mapping:
    //   - no evidence at all                → 0.30 (we know nothing)
    //   - some weak evidence, judged CLEAN  → 0.50–0.70
    //   - strong evidence (high score)      → scales with score
    //   - any CRITICAL finding              → ≥ 0.85 (unambiguous IOCs like
    //     a remote-shell postinstall script don't need probabilistic hedging;
    //     reporting a CRITICAL at 48% confidence undermined the BLOCK card)
    const evidenceWeight = Math.min(1, boundedScore / 60 + distinctCategories * 0.15);
    let confidence: number;
    if (verdict === "CLEAN") {
      if (distinctCategories === 0 && boundedScore === 0) {
        confidence = 0.3;
      } else {
        confidence = Math.min(0.85, 0.45 + 0.4 * (1 - evidenceWeight));
      }
    } else {
      const correlationBoost = Math.min(0.1, distinctCategories * 0.025);
      confidence = Math.min(0.99, Math.max(0.45, boundedScore / 100) + correlationBoost);
      if (highestSeverity === "CRITICAL") {
        confidence = Math.max(confidence, 0.85);
      }
    }

    return { verdict, confidence: Number(confidence.toFixed(2)) };
  }

  private buildRecommendations(input: VerdictInputs, verdict: HuskVerdict["verdict"]): string[] {
    const recommendations = new Set<string>();

    if (input.typosquat) {
      recommendations.add(`Use ${input.typosquat.target} instead of ${input.metadata.name}; the current name closely resembles a popular package.`);
    }

    if (input.behaviorDiff?.previousVersion && !["none", "unknown"].includes(input.behaviorDiff.previousVersion) && verdict !== "CLEAN") {
      recommendations.add(
        `Pin ${input.metadata.name} to the previous version ${input.behaviorDiff.previousVersion} until the new release is manually reviewed.`
      );
    }

    const hasSecretAccess =
      input.iocs.some((match) => /token|secret|environment-variable exfiltration|credential/i.test(match.description)) ||
      input.sandboxResult?.findings.some((finding) => /credential|secret/i.test(finding.description)) ||
      input.deobfuscation?.revealedSinks.some((sink) => sink.startsWith("env:"));
    if (hasSecretAccess) {
      recommendations.add("Rotate npm, GitHub, cloud, and CI credentials that may have been exposed on this machine.");
    }

    const hasWorkflowTampering =
      input.iocs.some((match) => /\.github\/workflows|workflow/i.test(match.evidence) || /workflow/i.test(match.description)) ||
      input.sandboxResult?.findings.some((finding) => finding.ruleId === "workflow-write");
    if (hasWorkflowTampering) {
      recommendations.add("Audit .github/workflows for unauthorized files or edits and revert any untrusted workflow changes.");
    }

    const hasInstallScripts = Object.keys(input.metadata.installScripts).length > 0;
    if (verdict !== "CLEAN" && hasInstallScripts) {
      recommendations.add(`If you must inspect this package further, use --ignore-scripts first so install hooks do not execute during triage.`);
    }

    if (!recommendations.size && verdict === "CLEAN") {
      recommendations.add("No blocking action recommended. Continue monitoring future updates.");
    } else if (!recommendations.size) {
      recommendations.add("Block the package from installation until it has been manually reviewed.");
    }

    return Array.from(recommendations).slice(0, 5);
  }

  private sortReasons(reasons: VerdictReason[]): VerdictReason[] {
    const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return [...reasons].sort((left, right) => order[right.severity] - order[left.severity] || right.scoreImpact - left.scoreImpact);
  }
}
