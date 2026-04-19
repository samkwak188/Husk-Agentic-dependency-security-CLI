import { access, readFile } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { resolve } from "node:path";

import { z } from "zod";

import { projectPath } from "./project-root.js";
import type { HuskVerdict, PolicyDecision } from "./types.js";

const verdictSchema = z.enum(["MALICIOUS", "SUSPICIOUS", "CLEAN"]);
const policySchema = z.object({
  name: z.string().default("default"),
  blockVerdicts: z.array(verdictSchema).default(["MALICIOUS"]),
  warnVerdicts: z.array(verdictSchema).default(["SUSPICIOUS"]),
  blockOnCriticalIocs: z.boolean().default(true),
  blockOnSecretExposure: z.boolean().default(true),
  blockOnWorkflowTampering: z.boolean().default(true),
  blockOnTyposquatDistance: z.number().int().nonnegative().nullable().default(1),
  reviewSuspiciousPackages: z.boolean().default(true)
});

type HuskPolicy = z.infer<typeof policySchema>;

const DEFAULT_POLICY: HuskPolicy = policySchema.parse({});

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path, fsConstants.R_OK);
    return true;
  } catch {
    return false;
  }
}

async function readPolicyFile(path: string): Promise<HuskPolicy | undefined> {
  if (!(await pathExists(path))) {
    return undefined;
  }

  const raw = await readFile(path, "utf8");
  return policySchema.parse(JSON.parse(raw));
}

/**
 * Resolve the policy in this priority order:
 *   1. HUSK_POLICY_PATH env var (explicit override)
 *   2. cwd-local: <cwd>/husk.policy.json or <cwd>/.husk/policy.json
 *      (lets a downstream user pin a stricter policy in their own repo)
 *   3. project-bundled: <PROJECT_ROOT>/husk.policy.json
 *      (so `husk` from any cwd still finds the policy that ships with Husk)
 *   4. DEFAULT_POLICY (hard-coded baseline)
 */
export async function loadPolicy(cwd = process.cwd()): Promise<HuskPolicy> {
  const envPath = process.env.HUSK_POLICY_PATH ? resolve(process.env.HUSK_POLICY_PATH) : undefined;
  const candidates = [
    envPath,
    resolve(cwd, "husk.policy.json"),
    resolve(cwd, ".husk/policy.json"),
    projectPath("husk.policy.json"),
    projectPath(".husk/policy.json")
  ].filter((candidate): candidate is string => Boolean(candidate));

  for (const candidate of candidates) {
    const loaded = await readPolicyFile(candidate);
    if (loaded) {
      return loaded;
    }
  }

  return DEFAULT_POLICY;
}

/**
 * Env-variable name *segments* that look like credentials. Matched as
 * underscore-separated tokens against a name like `NPM_TOKEN` so we don't
 * accidentally fire on substrings (e.g. `PAT` inside `PATH`, which was
 * blocking mongodb on `MONGODB_LOG_PATH`). The match is on segments, not
 * raw substrings.
 */
const CREDENTIAL_NAME_TOKENS = new Set([
  "TOKEN",
  "TOKENS",
  "KEY",
  "KEYS",
  "SECRET",
  "SECRETS",
  "PASSWORD",
  "PASSWD",
  "PASS",
  "AUTH",
  "CREDENTIAL",
  "CREDENTIALS",
  "APIKEY",
  "PAT",
  "PATS",
  "BEARER",
  "SESSION",
  "COOKIE",
  "COOKIES",
  "PRIVATE"
]);

function envSinkLooksLikeCredential(sink: string): boolean {
  // Sinks are formatted as `env:<NAME>` by the deobfuscator's suspicion
  // scorer. We tokenize <NAME> on `_` / `-` / camelCase boundaries and
  // check whether any token is a known credential keyword. This is what
  // distinguishes NPM_TOKEN (credential) from MONGODB_LOG_PATH (config).
  if (!sink.startsWith("env:")) return false;
  const name = sink.slice(4);
  const tokens = name
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .toUpperCase()
    .split(/[_\-.]/)
    .filter(Boolean);
  return tokens.some((t) => CREDENTIAL_NAME_TOKENS.has(t));
}

function hasSecretExposure(verdict: HuskVerdict): boolean {
  // Only fire on actual evidence of credential targeting. The previous
  // version's "any env: sink" heuristic blocked every package that reads
  // its own configuration (mongodb, eslint, dotenv itself).
  return (
    verdict.iocs.some((match) => /credential file|credential exfiltration|secret harvest|token theft|environment-variable exfiltration/i.test(match.description)) ||
    verdict.reasons.some(
      (reason) =>
        (reason.severity === "CRITICAL" || reason.severity === "HIGH") &&
        (/credential|secret|token|exfil/i.test(reason.title) || /\.npmrc|\.aws\/credentials|\.pypirc|GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET/i.test(reason.evidence ?? ""))
    ) ||
    verdict.deobfuscation?.revealedSinks.some(envSinkLooksLikeCredential) === true
  );
}

function hasWorkflowTampering(verdict: HuskVerdict): boolean {
  // Only fire on HIGH/CRITICAL workflow signals OR the literal `.github/workflows`
  // path appearing alongside a write call (which is what the IOC pattern
  // already requires). MEDIUM-severity workflow IOCs are too noisy on legit
  // CI scaffolders (playwright, gh-workflow-cli, semantic-release, etc.) to
  // drive a hard policy BLOCK on their own.
  return (
    verdict.iocs.some(
      (match) =>
        (match.severity === "CRITICAL" || match.severity === "HIGH") &&
        /\.github\/workflows|workflow.*propagation|worm/i.test(`${match.description} ${match.evidence ?? ""}`)
    ) ||
    verdict.reasons.some(
      (reason) =>
        (reason.severity === "CRITICAL" || reason.severity === "HIGH") &&
        /\.github\/workflows|worm/i.test(`${reason.title} ${reason.evidence ?? ""}`)
    )
  );
}

export class PolicyEngine {
  async evaluate(verdict: HuskVerdict, cwd = process.cwd()): Promise<PolicyDecision> {
    const policy = await loadPolicy(cwd);
    const blockReasons: string[] = [];
    const warnReasons: string[] = [];

    if (policy.blockVerdicts.includes(verdict.verdict)) {
      blockReasons.push(`Policy blocks packages classified as ${verdict.verdict}.`);
    } else if (policy.warnVerdicts.includes(verdict.verdict)) {
      warnReasons.push(`Policy requires review for packages classified as ${verdict.verdict}.`);
    }

    if (policy.blockOnCriticalIocs && verdict.iocs.some((match) => match.severity === "CRITICAL")) {
      blockReasons.push("Critical indicators of compromise were found in the package contents.");
    }

    if (policy.blockOnSecretExposure && hasSecretExposure(verdict)) {
      blockReasons.push("The package appears capable of reading or exfiltrating secrets or environment credentials.");
    }

    if (policy.blockOnWorkflowTampering && hasWorkflowTampering(verdict)) {
      blockReasons.push("The package appears to modify CI or GitHub workflow files.");
    }

    if (
      policy.blockOnTyposquatDistance !== null &&
      verdict.typosquat &&
      verdict.typosquat.distance <= policy.blockOnTyposquatDistance
    ) {
      blockReasons.push(`The package name is within typosquat distance ${policy.blockOnTyposquatDistance} of ${verdict.typosquat.target}.`);
    }

    if (policy.reviewSuspiciousPackages && verdict.verdict === "SUSPICIOUS") {
      warnReasons.push("Manual review is required before installation.");
    }

    if (blockReasons.length) {
      return {
        action: "BLOCK",
        summary: blockReasons[0],
        reasons: blockReasons,
        policyName: policy.name,
        canOverride: true,
        reviewRequired: true
      };
    }

    if (warnReasons.length) {
      return {
        action: "WARN",
        summary: warnReasons[0],
        reasons: warnReasons,
        policyName: policy.name,
        canOverride: true,
        reviewRequired: true
      };
    }

    return {
      action: "ALLOW",
      summary: "No policy rule requires blocking or manual review.",
      reasons: ["The package passed Husk's current policy checks."],
      policyName: policy.name,
      canOverride: false,
      reviewRequired: false
    };
  }
}
