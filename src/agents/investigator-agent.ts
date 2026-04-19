import { readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";

import { glob } from "glob";
import { z } from "zod";

import type { HuskVerdict, InvestigationResult } from "../core/types.js";
import { getAIWorkflowClient } from "./ai-workflow.js";

/**
 * Maximum cost we're willing to pay per investigation:
 *   - Up to 3 files chosen by the agent.
 *   - Each file capped at 200 lines or 8 KB (whichever is smaller).
 *   - Two AI calls total: one to plan, one to synthesize.
 *
 * In practice this adds ~5-10 s and ~3-5 K tokens per *borderline* scan.
 * Most scans are not borderline (clear ALLOW or clear BLOCK), so the
 * average wall-time impact across a run is ~1-2 minutes for 100 packages.
 */
const MAX_FILES_TO_INSPECT = 3;
const MAX_LINES_PER_FILE = 200;
const MAX_BYTES_PER_FILE = 8_192;
const MAX_FILES_IN_MENU = 30;

const PlanSchema = z.object({
  proceed: z
    .boolean()
    .describe(
      "Whether further investigation is warranted. Set false if the current evidence is already enough to make a confident verdict (in either direction)."
    ),
  filesToInspect: z
    .array(z.string())
    .max(MAX_FILES_TO_INSPECT)
    .describe(
      `Up to ${MAX_FILES_TO_INSPECT} file paths from the menu, chosen because they're most likely to contain decisive evidence. Use exact paths from the menu.`
    ),
  focusQuestion: z
    .string()
    .min(8)
    .max(220)
    .describe(
      "A single concrete question you want answered by reading those files (e.g. 'is the eval call resolving to user input or a constant?')."
    ),
  reasoning: z
    .string()
    .min(8)
    .max(280)
    .describe("Brief explanation of why these files and this question.")
});

const SynthesisSchema = z.object({
  recommendation: z
    .enum(["promote-to-malicious", "promote-to-suspicious", "downgrade-to-clean", "no-change"])
    .describe(
      "Verdict adjustment. Be conservative — prefer 'no-change' when evidence is ambiguous. Only 'promote-to-malicious' if the inspected files contain a concrete attack chain (e.g. credential read + outbound network), only 'downgrade-to-clean' if the inspected files clearly explain the prior signal as legitimate library behavior."
    ),
  confidence: z
    .number()
    .min(0)
    .max(1)
    .describe("Your confidence in this recommendation, 0-1. Use < 0.5 if you're guessing."),
  rationale: z
    .string()
    .min(8)
    .max(320)
    .describe("Cite the specific code or pattern in the inspected files that drove the recommendation.")
});

interface InvestigationContext {
  packagePath: string;
  packageName: string;
  packageVersion: string;
  verdict: HuskVerdict;
}

interface FileMenuEntry {
  path: string;
  bytes: number;
  hint: string;
}

/**
 * Determine whether a verdict is "borderline" enough to warrant the
 * autonomous loop. We deliberately gate this aggressively — investigating
 * every scan would multiply latency and API cost without proportional
 * accuracy gain. The borderline cases the FN list shows are exactly the
 * ones where one MEDIUM-severity finding fired but the multi-signal rule
 * suppressed it.
 */
export function shouldInvestigate(verdict: HuskVerdict): { borderline: boolean; reason: string } {
  // Explicit registry takedowns and CRITICAL signals are not borderline —
  // re-investigation can't help and only adds latency.
  const hasCritical = (verdict.iocs ?? []).some((m) => m.severity === "CRITICAL") ||
    (verdict.reasons ?? []).some((r) => r.severity === "CRITICAL");
  if (hasCritical) return { borderline: false, reason: "critical-signal-present" };

  // Exclude clearly clean packages that triggered nothing — investigating
  // these is just noise. The empty-package detector already catches the
  // dependency-confusion subset.
  const hasAnySignal = (verdict.reasons ?? []).length > 0;
  if (verdict.verdict === "CLEAN" && !hasAnySignal) {
    return { borderline: false, reason: "clean-no-signals" };
  }

  // Three borderline cases:
  //   1. SUSPICIOUS at moderate confidence — could be a real catch or an FP.
  //   2. MALICIOUS at moderate confidence — Husk says "this is malware"
  //      while only 50-70% sure. Investigator can corroborate by reading
  //      the actual code. Hard guards in applyInvestigation prevent the
  //      agent from talking away CRITICAL signals; for HIGH-driven
  //      MALICIOUS verdicts the agent CAN downgrade, which is the right
  //      behavior for FPs that survived the rule layer.
  //   3. CLEAN with at least one HIGH or multiple MEDIUM signals that
  //      almost-but-didn't promote.
  if (verdict.verdict === "SUSPICIOUS" && verdict.confidence < 0.7) {
    return { borderline: true, reason: "suspicious-low-confidence" };
  }
  if (verdict.verdict === "MALICIOUS" && verdict.confidence < 0.7) {
    return { borderline: true, reason: "malicious-low-confidence" };
  }
  const hasHighReason = (verdict.reasons ?? []).some((r) => r.severity === "HIGH");
  const mediumCount = (verdict.reasons ?? []).filter((r) => r.severity === "MEDIUM").length;
  if (verdict.verdict === "CLEAN" && (hasHighReason || mediumCount >= 1)) {
    return { borderline: true, reason: "clean-with-suppressed-signal" };
  }

  return { borderline: false, reason: "verdict-confident" };
}

async function buildFileMenu(packagePath: string): Promise<FileMenuEntry[]> {
  const files = await glob("**/*.{js,cjs,mjs,ts,tsx}", {
    cwd: packagePath,
    nodir: true,
    dot: false,
    ignore: [
      "**/node_modules/**",
      "**/.git/**",
      "**/dist/**",
      "**/build/**",
      "**/*.d.ts",
      "**/*.min.js",
      "**/*.min.cjs",
      "**/*.umd.js",
      "**/*.bundle.js",
      "**/test/**",
      "**/__tests__/**",
      "**/*.test.*",
      "**/*.spec.*"
    ]
  });

  const entries: FileMenuEntry[] = [];
  for (const file of files.slice(0, MAX_FILES_IN_MENU)) {
    try {
      const s = await stat(join(packagePath, file));
      const hint = inferFileHint(file);
      entries.push({ path: file, bytes: s.size, hint });
    } catch {
      // ignore unreadable
    }
  }

  // Sort largest-first so the agent sees the meaty files near the top.
  entries.sort((a, b) => b.bytes - a.bytes);
  return entries;
}

/**
 * Best-effort heuristic for what's likely in a file based on its path.
 * Helps the planner choose intelligently without reading every file.
 */
function inferFileHint(path: string): string {
  const lower = path.toLowerCase();
  if (lower.includes("install") || lower.includes("setup") || lower.includes("postinstall")) return "lifecycle / install";
  if (lower.includes("auth") || lower.includes("credential") || lower.includes("token")) return "auth / credentials";
  if (lower.includes("network") || lower.includes("http") || lower.includes("fetch")) return "network";
  if (lower.includes("worker") || lower.includes("agent")) return "background work";
  if (lower.endsWith("/index.js") || lower.endsWith("/index.ts") || lower.endsWith("/main.js")) return "entry point";
  if (lower.includes("util") || lower.includes("helper")) return "utility";
  return "general";
}

async function readFileBudgeted(filePath: string): Promise<string> {
  try {
    const content = await readFile(filePath, "utf8");
    const sliced = content.slice(0, MAX_BYTES_PER_FILE);
    const lines = sliced.split("\n").slice(0, MAX_LINES_PER_FILE);
    if (lines.length === MAX_LINES_PER_FILE) {
      lines.push(`// ...[truncated by Husk after ${MAX_LINES_PER_FILE} lines]`);
    }
    return lines.join("\n");
  } catch {
    return "";
  }
}

function summarizeReasonsForPrompt(verdict: HuskVerdict): string {
  const reasons = verdict.reasons ?? [];
  if (reasons.length === 0) return "  (no detector signals fired)";
  return reasons
    .slice(0, 8)
    .map((r) => `  - [${r.severity}] ${r.title}\n    Evidence: ${(r.evidence ?? "").replace(/\s+/g, " ").slice(0, 240)}`)
    .join("\n");
}

function summarizeMenuForPrompt(menu: FileMenuEntry[]): string {
  if (menu.length === 0) return "  (no inspectable files)";
  return menu
    .map((e, i) => `  ${i + 1}. ${e.path}  (${e.bytes} B, hint: ${e.hint})`)
    .join("\n");
}

const PLAN_INSTRUCTIONS = `You are Husk's investigation agent. You only get called when Husk's first-pass detectors found something interesting but the multi-signal correlation rule didn't promote it to a verdict — these are precisely the borderline cases that benefit most from a closer look.

Default to proceed=true. The first pass is rule-based and already declined to commit; your job is to read the actual code that triggered the signal and decide whether the rule was right or wrong to suppress it. If you set proceed=false you are saying "the existing evidence speaks for itself" — only do that when the prior signals are themselves dispositive (e.g. a CRITICAL IOC that already drove a hard verdict, or a clearly-clean package with literally zero signals).

When proceed=true:
  1. Choose up to ${MAX_FILES_TO_INSPECT} files from the menu most likely to contain the code the prior signals point to. Use the file path hints, the signal evidence text, and any file paths mentioned in the evidence itself. Pick the file containing the cited evidence first whenever it's named.
  2. Frame ONE concrete question you want answered when you read those files (e.g. "is the env-var read passing the value to a network call, or just to console.log?").

You will be CALLED AGAIN with the file contents to make the actual recommendation. You are conservative on the recommendation, NOT on whether to look. Looking is cheap; being wrong is expensive.`;

const SYNTHESIS_INSTRUCTIONS = `You are Husk's investigation agent — synthesizing what you read into a verdict adjustment.

Recommendation rules (be conservative):
  - "promote-to-malicious": ONLY if the inspected files contain a concrete attack chain (e.g. credential read followed by outbound network call, obfuscated process spawn, environment exfiltration to a non-registry host). The standard is high — accidental high-severity matches in legitimate library code do NOT qualify.
  - "promote-to-suspicious": when the inspected files corroborate the prior signals enough that a developer should review before installing.
  - "downgrade-to-clean": when the inspected files clearly explain the prior signal as legitimate behavior (e.g. an env-var read for a library config option, a URL embedded in a comment).
  - "no-change": preferred when ambiguous. Honest uncertainty beats wrong confidence.

Cite the specific code or pattern in your rationale. Do not invent evidence the files don't contain.`;

export class InvestigatorAgent {
  async investigate(context: InvestigationContext): Promise<InvestigationResult> {
    const startedAt = Date.now();
    const trigger = shouldInvestigate(context.verdict);

    if (!trigger.borderline) {
      return {
        triggered: false,
        reason: trigger.reason,
        filesInspected: [],
        recommendation: "no-change",
        agentConfidence: 0,
        rationale: "Verdict was not borderline — re-investigation skipped.",
        durationMs: Date.now() - startedAt
      };
    }

    const ai = getAIWorkflowClient();
    if (!ai.isEnabled()) {
      return {
        triggered: false,
        reason: "ai-disabled",
        filesInspected: [],
        recommendation: "no-change",
        agentConfidence: 0,
        rationale: "AI workflow is not configured (no API key); re-investigation skipped.",
        durationMs: Date.now() - startedAt
      };
    }

    const menu = await buildFileMenu(context.packagePath);
    if (menu.length === 0) {
      return {
        triggered: false,
        reason: "no-inspectable-files",
        filesInspected: [],
        recommendation: "no-change",
        agentConfidence: 0,
        rationale: "Package contains no inspectable source files.",
        durationMs: Date.now() - startedAt
      };
    }

    const planInput = [
      `Package: ${context.packageName}@${context.packageVersion}`,
      `Current verdict: ${context.verdict.verdict} (confidence ${Math.round((context.verdict.confidence ?? 0) * 100)}%)`,
      `Why we're re-investigating: ${trigger.reason}`,
      "",
      "Detector signals fired in the first pass:",
      summarizeReasonsForPrompt(context.verdict),
      "",
      `Available files (max ${MAX_FILES_IN_MENU} shown, sorted by size):`,
      summarizeMenuForPrompt(menu)
    ].join("\n");

    const plan = await ai.createStructuredResponse({
      stage: "investigation",
      schemaName: "InvestigationPlan",
      schema: PlanSchema,
      instructions: PLAN_INSTRUCTIONS,
      input: planInput
    });

    if (!plan) {
      const stageError = ai.describeStage("investigation").error;
      const errMsg = stageError
        ? `${stageError.code ?? stageError.type ?? stageError.status ?? "unknown"}: ${stageError.message}`
        : "no error reported";
      return {
        triggered: true,
        reason: trigger.reason,
        filesInspected: [],
        recommendation: "no-change",
        agentConfidence: 0,
        rationale: `Planner call failed (${errMsg}).`,
        durationMs: Date.now() - startedAt
      };
    }
    if (!plan.proceed) {
      return {
        triggered: true,
        reason: trigger.reason,
        filesInspected: [],
        focusQuestion: plan.focusQuestion,
        recommendation: "no-change",
        agentConfidence: 0.5,
        rationale: `Planner declined to proceed: ${plan.reasoning}`,
        durationMs: Date.now() - startedAt
      };
    }
    if (plan.filesToInspect.length === 0) {
      return {
        triggered: true,
        reason: trigger.reason,
        filesInspected: [],
        focusQuestion: plan.focusQuestion,
        recommendation: "no-change",
        agentConfidence: 0.3,
        rationale: `Planner proceeded but selected no files. Reasoning: ${plan.reasoning}`,
        durationMs: Date.now() - startedAt
      };
    }

    // Validate: only allow files actually present in the menu (defense
    // against the LLM hallucinating paths).
    const menuPaths = new Set(menu.map((e) => e.path));
    const validFiles = plan.filesToInspect.filter((f) => menuPaths.has(f)).slice(0, MAX_FILES_TO_INSPECT);
    if (validFiles.length === 0) {
      return {
        triggered: true,
        reason: trigger.reason,
        filesInspected: [],
        focusQuestion: plan.focusQuestion,
        recommendation: "no-change",
        agentConfidence: 0,
        rationale: "Planner returned file paths not present in the package.",
        durationMs: Date.now() - startedAt
      };
    }

    const fileBlocks: string[] = [];
    for (const file of validFiles) {
      const absPath = join(context.packagePath, file);
      const body = await readFileBudgeted(absPath);
      const rel = relative(context.packagePath, absPath);
      fileBlocks.push(`### File: ${rel}\n\`\`\`\n${body}\n\`\`\``);
    }

    const synthInput = [
      `Package: ${context.packageName}@${context.packageVersion}`,
      `Prior verdict: ${context.verdict.verdict} (confidence ${Math.round((context.verdict.confidence ?? 0) * 100)}%)`,
      "",
      "Prior detector signals:",
      summarizeReasonsForPrompt(context.verdict),
      "",
      `Focus question: ${plan.focusQuestion}`,
      "",
      "Files you chose to inspect:",
      ...fileBlocks
    ].join("\n");

    const synthesis = await ai.createStructuredResponse({
      stage: "investigation",
      schemaName: "InvestigationSynthesis",
      schema: SynthesisSchema,
      instructions: SYNTHESIS_INSTRUCTIONS,
      input: synthInput
    });

    if (!synthesis) {
      return {
        triggered: true,
        reason: trigger.reason,
        filesInspected: validFiles,
        focusQuestion: plan.focusQuestion,
        recommendation: "no-change",
        agentConfidence: 0,
        rationale: "Synthesis call returned no structured response.",
        durationMs: Date.now() - startedAt
      };
    }

    return {
      triggered: true,
      reason: trigger.reason,
      filesInspected: validFiles,
      focusQuestion: plan.focusQuestion,
      recommendation: synthesis.recommendation,
      agentConfidence: synthesis.confidence,
      rationale: synthesis.rationale,
      durationMs: Date.now() - startedAt
    };
  }
}

/**
 * Apply an investigation recommendation to a verdict. Verdict severity
 * can only move within bounds: never escalate past MALICIOUS, never
 * downgrade away from a verdict that has CRITICAL signals (defense
 * against agent hallucination — a CRITICAL IOC is a hard fact).
 */
export function applyInvestigation(verdict: HuskVerdict, result: InvestigationResult): HuskVerdict {
  if (!result.triggered || result.recommendation === "no-change") {
    return { ...verdict, investigation: result };
  }
  if (result.agentConfidence < 0.5) {
    // Low-confidence agent recommendations are recorded for transparency
    // but not applied — better to leave the deterministic verdict alone
    // than overwrite it with a guess.
    return { ...verdict, investigation: result };
  }

  let updated: HuskVerdict = { ...verdict, investigation: result };
  const hasCritical = (verdict.iocs ?? []).some((m) => m.severity === "CRITICAL");

  switch (result.recommendation) {
    case "promote-to-malicious": {
      updated.verdict = "MALICIOUS";
      updated.confidence = Math.max(verdict.confidence, Math.min(0.95, result.agentConfidence));
      updated.reasons = [
        ...verdict.reasons,
        {
          severity: "HIGH",
          scoreImpact: 30,
          title: "Investigator agent escalated to MALICIOUS",
          evidence: result.rationale
        }
      ];
      break;
    }
    case "promote-to-suspicious": {
      if (verdict.verdict !== "MALICIOUS") updated.verdict = "SUSPICIOUS";
      updated.confidence = Math.max(verdict.confidence, Math.min(0.85, result.agentConfidence));
      updated.reasons = [
        ...verdict.reasons,
        {
          severity: "MEDIUM",
          scoreImpact: 15,
          title: "Investigator agent escalated to SUSPICIOUS",
          evidence: result.rationale
        }
      ];
      break;
    }
    case "downgrade-to-clean": {
      // Hard guard 1: never downgrade if there's a CRITICAL IOC.
      // CRITICAL findings are deterministic facts, not subjective signals
      // the AI can talk away.
      if (hasCritical) return { ...verdict, investigation: result };
      // Hard guard 2: downgrades from MALICIOUS require very high agent
      // confidence (>= 0.8). Upgrades only need 0.5. The asymmetry is
      // deliberate — false-negatives on real malware are much more
      // damaging than leaving a borderline FP at SUSPICIOUS.
      if (verdict.verdict === "MALICIOUS" && result.agentConfidence < 0.8) {
        return { ...verdict, investigation: result };
      }
      updated.verdict = "CLEAN";
      updated.confidence = Math.max(0.5, Math.min(0.8, result.agentConfidence));
      updated.reasons = [
        ...verdict.reasons,
        {
          severity: "LOW",
          scoreImpact: 0,
          title: "Investigator agent downgraded to CLEAN",
          evidence: result.rationale
        }
      ];
      break;
    }
  }

  return updated;
}
