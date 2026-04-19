import "../src/core/project-root.js";

// Fast-iteration mode: when HUSK_BENCHMARK_NO_AI is set, strip the AI
// provider keys before any subsystem reads them. The orchestrator falls
// back to its deterministic agents and benchmark wall time drops from
// ~30 minutes to ~2 minutes. Useful for measuring the heuristic layer in
// isolation while iterating on detector rules.
if (process.env.HUSK_BENCHMARK_NO_AI === "1" || process.env.HUSK_BENCHMARK_NO_AI === "true") {
  delete process.env.OPENAI_API_KEY;
  delete process.env.OPENROUTER_API_KEY;
  delete process.env.AI_PROVIDER;
  // Surface the override so it appears in the Mode banner of the report.
  process.env.HUSK_AI_FORCED_OFF = "1";
}

import { execSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { arch, platform } from "node:os";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

import chalk from "chalk";
import ora from "ora";

import { HuskOrchestrator } from "../src/agents/orchestrator.js";
import { POPULAR_PACKAGES } from "../src/subsystems/typosquat/popular-packages.js";
import { extractGroundTruthZip, loadGroundTruth } from "./loader.js";
import {
  calculateBenchmarkMetrics,
  computeBaselines,
  detectLeakage,
  extractTopFalseNegatives,
  extractTopFalsePositives,
  generateMarkdownReport,
  renderTerminalReport,
  type BenchmarkCaseResult,
  type BenchmarkProvenance,
  type TerminalReportContext
} from "./report.js";

function isDetected(verdict: Awaited<ReturnType<HuskOrchestrator["analyze"]>>): boolean {
  return verdict.verdict === "MALICIOUS" || verdict.verdict === "SUSPICIOUS";
}

function pickTopReason(verdict: Awaited<ReturnType<HuskOrchestrator["analyze"]>>): { title?: string; evidence?: string } {
  const reasons = verdict.reasons ?? [];
  if (reasons.length === 0) return {};
  const severityOrder: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const sorted = reasons
    .slice()
    .sort((a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0) || b.scoreImpact - a.scoreImpact);
  return { title: sorted[0].title, evidence: sorted[0].evidence };
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.floor((ms % 60_000) / 1000);
  return `${minutes}m${seconds.toString().padStart(2, "0")}s`;
}

function progressBar(done: number, total: number, width = 24): string {
  const ratio = total === 0 ? 0 : done / total;
  const filled = Math.round(ratio * width);
  const bar = `${"█".repeat(filled)}${"░".repeat(width - filled)}`;
  const pct = `${Math.round(ratio * 100).toString().padStart(3)}%`;
  return `${chalk.green(bar)} ${chalk.dim(pct)}`;
}

interface ProgressTracker {
  tick: (label: string, detected: boolean, durationMs: number) => void;
  finish: () => void;
}

function createProgressTracker(total: number): ProgressTracker {
  const startedAt = Date.now();
  let done = 0;
  let detectedCount = 0;
  let totalScanMs = 0;

  const isTty = Boolean(process.stdout.isTTY);
  const spinner = isTty
    ? ora({
        text: `${progressBar(0, total)}  ${chalk.dim(`0/${total}`)}`,
        spinner: { interval: 90, frames: ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"] },
        color: "green"
      }).start()
    : null;

  const ticker = isTty
    ? setInterval(() => {
        if (!spinner) return;
        const elapsed = Date.now() - startedAt;
        spinner.text =
          `${progressBar(done, total)}  ` +
          `${chalk.bold(`${done}/${total}`)} ${chalk.dim(`elapsed ${formatDuration(elapsed)}`)}`;
      }, 500)
    : null;

  return {
    tick(label: string, detected: boolean, durationMs: number) {
      done += 1;
      totalScanMs += durationMs;
      if (detected) detectedCount += 1;
      if (spinner) {
        const elapsed = Date.now() - startedAt;
        const avg = totalScanMs / done;
        const remaining = Math.max(0, total - done);
        const eta = Math.round((remaining * avg) / 1000);
        spinner.text =
          `${progressBar(done, total)}  ` +
          `${chalk.bold(`${done}/${total}`)} ` +
          `${chalk.dim(`· last ${label} ${detected ? chalk.yellow("flagged") : chalk.green("clean")} ${formatDuration(durationMs)}`)} ` +
          `${chalk.dim(`· elapsed ${formatDuration(elapsed)} · eta ${eta}s`)}`;
      } else {
        process.stdout.write(
          `[${done}/${total}] ${label} ${detected ? "flagged" : "clean"} (${formatDuration(durationMs)})\n`
        );
      }
    },
    finish() {
      if (ticker) clearInterval(ticker);
      if (spinner) {
        const elapsed = Date.now() - startedAt;
        spinner.succeed(
          `${chalk.green("Benchmark complete")} ${chalk.dim(`· ${total} packages · ${detectedCount} flagged · ${formatDuration(elapsed)}`)}`
        );
      }
    }
  };
}

async function collectProvenance(args: {
  durationMs: number;
  staticOnly: boolean;
  datasetSizes: { malicious: number; benign: number };
  aiEnabled: boolean;
  aiProvider: string;
  seed: number | null;
}): Promise<BenchmarkProvenance> {
  let huskVersion = "unknown";
  try {
    const pkg = JSON.parse(await readFile(resolve("package.json"), "utf8")) as { version?: string };
    huskVersion = pkg.version ?? "unknown";
  } catch {
    // ignore
  }

  let gitSha: string | null = null;
  let gitDirty: boolean | null = null;
  try {
    gitSha = execSync("git rev-parse HEAD", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
    const status = execSync("git status --porcelain", { stdio: ["ignore", "pipe", "ignore"] }).toString();
    gitDirty = status.trim().length > 0;
  } catch {
    gitSha = null;
    gitDirty = null;
  }

  return {
    huskVersion,
    gitSha,
    gitDirty,
    nodeVersion: process.version,
    platform: platform(),
    arch: arch(),
    timestamp: new Date().toISOString(),
    durationMs: args.durationMs,
    aiProvider: args.aiProvider,
    aiEnabled: args.aiEnabled,
    staticOnly: args.staticOnly,
    datasetSizes: args.datasetSizes,
    seed: args.seed
  };
}

function inferAiSettings(): { enabled: boolean; provider: string } {
  const hasOpenAi = Boolean(process.env.OPENAI_API_KEY);
  const hasOpenRouter = Boolean(process.env.OPENROUTER_API_KEY);
  if (hasOpenAi) return { enabled: true, provider: "openai" };
  if (hasOpenRouter) return { enabled: true, provider: "openrouter" };
  return { enabled: false, provider: "deterministic" };
}

export async function runBenchmark(): Promise<void> {
  const benchmarkStartedAt = Date.now();
  const orchestrator = new HuskOrchestrator();
  const groundTruth = await loadGroundTruth();
  const maliciousSample = groundTruth.filter((entry) => entry.ecosystem === "npm").slice(0, 50);
  const benignNames = POPULAR_PACKAGES.slice(0, 50);
  const results: BenchmarkCaseResult[] = [];
  const total = maliciousSample.length + benignNames.length;
  const staticOnly = true;

  console.log(
    chalk.bold(
      `\nRunning benchmark across ${total} packages (${maliciousSample.length} malicious, ${benignNames.length} benign)\n`
    )
  );

  const tracker = createProgressTracker(total);

  try {
    for (const entry of maliciousSample) {
      const extractedPath = await extractGroundTruthZip(entry.zipPath);
      try {
        const verdict = await orchestrator.analyze(extractedPath, {
          localPath: extractedPath,
          staticOnly
        });
        const detected = isDetected(verdict);
        const top = pickTopReason(verdict);
        results.push({
          name: entry.name,
          ecosystem: entry.ecosystem,
          label: "malicious",
          detected,
          confidence: verdict.confidence ?? 0,
          duration: verdict.scanDuration,
          category: entry.category,
          topReasonTitle: top.title,
          topReasonEvidence: top.evidence,
          sandboxRan: Boolean(verdict.sandboxResult)
        });
        tracker.tick(`malicious/${entry.category ?? "unknown"}`, detected, verdict.scanDuration);
      } finally {
        await rm(resolve(extractedPath, ".."), { recursive: true, force: true }).catch(() => undefined);
      }
    }

    for (const packageSpec of benignNames) {
      const verdict = await orchestrator.analyze(packageSpec, { staticOnly });
      const detected = isDetected(verdict);
      const top = pickTopReason(verdict);
      results.push({
        name: packageSpec,
        ecosystem: "npm",
        label: "benign",
        detected,
        confidence: verdict.confidence ?? 0,
        duration: verdict.scanDuration,
        topReasonTitle: top.title,
        topReasonEvidence: top.evidence,
        sandboxRan: Boolean(verdict.sandboxResult)
      });
      tracker.tick(`benign/${packageSpec}`, detected, verdict.scanDuration);
    }
  } finally {
    tracker.finish();
  }

  // ── Compute everything ────────────────────────────────────────────
  const metrics = calculateBenchmarkMetrics(results);
  const leakage = detectLeakage(benignNames, POPULAR_PACKAGES);
  const baselines = computeBaselines(results);
  const topFP = extractTopFalsePositives(results, 5);
  const topFN = extractTopFalseNegatives(results, 5);
  const ai = inferAiSettings();
  const provenance = await collectProvenance({
    durationMs: Date.now() - benchmarkStartedAt,
    staticOnly,
    datasetSizes: { malicious: maliciousSample.length, benign: benignNames.length },
    aiEnabled: ai.enabled,
    aiProvider: ai.provider,
    seed: null
  });

  const outputDir = await mkdtemp(join(tmpdir(), "husk-benchmark-"));
  const ctx: TerminalReportContext = {
    results,
    metrics,
    leakage,
    baselines,
    provenance,
    topFP,
    topFN,
    artifactsDir: outputDir
  };

  // ── Persist artifacts ─────────────────────────────────────────────
  await writeFile(join(outputDir, "benchmark-report.md"), generateMarkdownReport(ctx), "utf8");
  await writeFile(
    join(outputDir, "benchmark-report.json"),
    JSON.stringify(
      {
        provenance,
        metrics,
        leakage,
        baselines,
        topFP,
        topFN,
        // The full per-package results are the most valuable artifact for
        // auditing — every flagged benign and every missed malicious is
        // available with its top reason and evidence here.
        results
      },
      null,
      2
    ),
    "utf8"
  );

  // ── Print to terminal ─────────────────────────────────────────────
  console.log("");
  console.log(renderTerminalReport(ctx));
}

if (process.argv[1] && process.argv[1].endsWith("runner.ts") && existsSync(process.argv[1])) {
  void runBenchmark();
}
