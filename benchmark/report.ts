import chalk from "chalk";

import { box, renderTable } from "../src/cli/ui.js";

export interface BenchmarkCaseResult {
  name: string;
  ecosystem: "npm" | "pypi";
  label: "malicious" | "benign";
  detected: boolean;
  confidence: number;
  duration: number;
  category?: string;
  topReasonTitle?: string;
  topReasonEvidence?: string;
  sandboxRan?: boolean;
}

export interface ConfidenceInterval {
  lower: number;
  upper: number;
}

export interface RatioWithCI {
  rate: number;
  count: number;
  total: number;
  ci95: ConfidenceInterval;
}

export interface BenchmarkMetrics {
  totalPackagesTested: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: RatioWithCI;
  recall: RatioWithCI;
  fpRate: RatioWithCI;
  f1: number;
  f1Ci95: ConfidenceInterval;
  latency: { p50: number; p95: number; p99: number };
  categoryRates: Array<{ category: string; detected: number; total: number; rate: number; ci95: ConfidenceInterval }>;
}

export interface LeakageReport {
  benignTotal: number;
  benignOnAllowlist: number;
  allowlistShareOfBenign: number;
}

export interface BaselineComparison {
  name: string;
  description: string;
  precision: number;
  recall: number;
  f1: number;
  fpRate: number;
}

export interface BenchmarkProvenance {
  huskVersion: string;
  gitSha: string | null;
  gitDirty: boolean | null;
  nodeVersion: string;
  platform: string;
  arch: string;
  timestamp: string;
  durationMs: number;
  aiProvider: string;
  aiEnabled: boolean;
  staticOnly: boolean;
  datasetSizes: { malicious: number; benign: number };
  seed: number | null;
}

// ─── Statistics helpers ────────────────────────────────────────────────────

/**
 * Wilson score interval for a binomial proportion. Far better than the
 * normal approximation when counts are small, which is exactly the regime
 * the benchmark is in (n=50 per class).
 */
export function wilsonInterval(successes: number, trials: number, z = 1.96): ConfidenceInterval {
  if (trials <= 0) return { lower: 0, upper: 0 };
  const p = successes / trials;
  const z2 = z * z;
  const denominator = 1 + z2 / trials;
  const center = (p + z2 / (2 * trials)) / denominator;
  const margin = (z * Math.sqrt((p * (1 - p) + z2 / (4 * trials)) / trials)) / denominator;
  return {
    lower: Math.max(0, center - margin),
    upper: Math.min(1, center + margin)
  };
}

function ratio(count: number, total: number): RatioWithCI {
  return {
    rate: total > 0 ? count / total : 0,
    count,
    total,
    ci95: wilsonInterval(count, total)
  };
}

function f1FromCounts(tp: number, fp: number, fn: number): number {
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  return precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
}

/**
 * Bootstrap a 95% CI for F1 by resampling with replacement. Necessary
 * because F1 is a non-linear combination of two proportions and Wilson
 * doesn't apply directly. 1000 iterations is plenty for stable bounds at
 * benchmark sample sizes.
 */
export function bootstrapF1(results: BenchmarkCaseResult[], iterations = 1000, seed = 42): ConfidenceInterval {
  if (results.length === 0) return { lower: 0, upper: 0 };
  const rng = mulberry32(seed);
  const f1s: number[] = [];
  for (let i = 0; i < iterations; i++) {
    let tp = 0, fp = 0, fn = 0;
    for (let j = 0; j < results.length; j++) {
      const sample = results[Math.floor(rng() * results.length)];
      if (sample.label === "malicious" && sample.detected) tp++;
      else if (sample.label === "benign" && sample.detected) fp++;
      else if (sample.label === "malicious" && !sample.detected) fn++;
    }
    f1s.push(f1FromCounts(tp, fp, fn));
  }
  f1s.sort((a, b) => a - b);
  return {
    lower: f1s[Math.floor(0.025 * iterations)],
    upper: f1s[Math.floor(0.975 * iterations)]
  };
}

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function percentile(sortedValues: number[], q: number): number {
  if (sortedValues.length === 0) return 0;
  const idx = Math.min(sortedValues.length - 1, Math.floor(q * sortedValues.length));
  return sortedValues[idx];
}

// ─── Metric computation ────────────────────────────────────────────────────

export function calculateBenchmarkMetrics(results: BenchmarkCaseResult[]): BenchmarkMetrics {
  const malicious = results.filter((r) => r.label === "malicious");
  const benign = results.filter((r) => r.label === "benign");
  const truePositives = malicious.filter((r) => r.detected).length;
  const falseNegatives = malicious.length - truePositives;
  const falsePositives = benign.filter((r) => r.detected).length;
  const trueNegatives = benign.length - falsePositives;

  const precision = ratio(truePositives, truePositives + falsePositives);
  const recall = ratio(truePositives, malicious.length);
  const fpRate = ratio(falsePositives, benign.length);
  const f1 = f1FromCounts(truePositives, falsePositives, falseNegatives);
  const f1Ci95 = bootstrapF1(results);

  const sortedDurations = results.map((r) => r.duration).sort((a, b) => a - b);
  const latency = {
    p50: percentile(sortedDurations, 0.5),
    p95: percentile(sortedDurations, 0.95),
    p99: percentile(sortedDurations, 0.99)
  };

  const categories = new Map<string, { detected: number; total: number }>();
  for (const r of malicious) {
    const c = r.category ?? "uncategorized";
    const cur = categories.get(c) ?? { detected: 0, total: 0 };
    cur.total += 1;
    if (r.detected) cur.detected += 1;
    categories.set(c, cur);
  }

  return {
    totalPackagesTested: results.length,
    truePositives,
    falsePositives,
    trueNegatives,
    falseNegatives,
    precision,
    recall,
    fpRate,
    f1,
    f1Ci95,
    latency,
    categoryRates: [...categories.entries()].map(([category, data]) => ({
      category,
      detected: data.detected,
      total: data.total,
      rate: data.total ? data.detected / data.total : 0,
      ci95: wilsonInterval(data.detected, data.total)
    }))
  };
}

// ─── Data leakage detection ────────────────────────────────────────────────

export function detectLeakage(
  benignNames: string[],
  internalAllowlist: ReadonlyArray<string>
): LeakageReport {
  const allow = new Set(internalAllowlist.map((n) => n.toLowerCase()));
  const overlap = benignNames.filter((n) => allow.has(n.toLowerCase()));
  return {
    benignTotal: benignNames.length,
    benignOnAllowlist: overlap.length,
    allowlistShareOfBenign: benignNames.length > 0 ? overlap.length / benignNames.length : 0
  };
}

// ─── Baselines ─────────────────────────────────────────────────────────────

const NAIVE_NAME_REGEX = /(eval|exec|curl|wget|reverse|shell|miner|stealer|exfil|backdoor|payload|drop|crypt|loader|inject|sploit|attack)/i;

export function computeBaselines(results: BenchmarkCaseResult[]): BaselineComparison[] {
  const tally = (predict: (r: BenchmarkCaseResult) => boolean): BaselineComparison => {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (const r of results) {
      const positive = predict(r);
      if (r.label === "malicious" && positive) tp++;
      else if (r.label === "malicious" && !positive) fn++;
      else if (r.label === "benign" && positive) fp++;
      else tn++;
    }
    const precision = tp + fp ? tp / (tp + fp) : 0;
    const recall = tp + fn ? tp / (tp + fn) : 0;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
    const fpRate = fp + tn ? fp / (fp + tn) : 0;
    return { name: "", description: "", precision, recall, f1, fpRate };
  };

  return [
    {
      ...tally(() => false),
      name: "always-allow",
      description: "block nothing — what you get without any tool"
    },
    {
      ...tally(() => true),
      name: "always-block",
      description: "block everything — paranoid baseline, useless in practice"
    },
    {
      ...tally((r) => NAIVE_NAME_REGEX.test(r.name)),
      name: "name-keyword regex",
      description: "block if package name matches /eval|exec|curl|.../ — the dumbest heuristic"
    }
  ];
}

// ─── Top FP / FN extraction ────────────────────────────────────────────────

export function extractTopFalsePositives(results: BenchmarkCaseResult[], limit = 5): BenchmarkCaseResult[] {
  return results
    .filter((r) => r.label === "benign" && r.detected)
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, limit);
}

export function extractTopFalseNegatives(results: BenchmarkCaseResult[], limit = 5): BenchmarkCaseResult[] {
  return results
    .filter((r) => r.label === "malicious" && !r.detected)
    .sort((a, b) => a.confidence - b.confidence)
    .slice(0, limit);
}

// ─── Rendering ─────────────────────────────────────────────────────────────

const PALETTE = {
  safe: chalk.hex("#34d399"),
  warn: chalk.hex("#fbbf24"),
  danger: chalk.hex("#f87171"),
  accent: chalk.hex("#60a5fa"),
  highlight: chalk.hex("#c4b5fd"),
  muted: chalk.hex("#9ca3af"),
  border: chalk.hex("#475569")
};

function pct(v: number): string { return `${(v * 100).toFixed(1)}%`; }
function fmtCi(ci: ConfidenceInterval): string { return `[${pct(ci.lower)}, ${pct(ci.upper)}]`; }
function fmtMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.floor((ms % 60_000) / 1000);
  return `${m}m${s.toString().padStart(2, "0")}s`;
}

function verdictColor(rate: number, invert = false): chalk.Chalk {
  const score = invert ? 1 - rate : rate;
  if (score >= 0.85) return PALETTE.safe;
  if (score >= 0.6) return PALETTE.warn;
  return PALETTE.danger;
}

function truncate(text: string, max: number): string {
  if (!text) return "";
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length <= max ? collapsed : `${collapsed.slice(0, max - 1)}…`;
}

export interface TerminalReportContext {
  results: BenchmarkCaseResult[];
  metrics: BenchmarkMetrics;
  leakage: LeakageReport;
  baselines: BaselineComparison[];
  provenance: BenchmarkProvenance;
  topFP: BenchmarkCaseResult[];
  topFN: BenchmarkCaseResult[];
  artifactsDir?: string;
}

export function renderTerminalReport(ctx: TerminalReportContext): string {
  const { metrics, leakage, baselines, provenance, topFP, topFN } = ctx;
  const lines: string[] = [];

  // ── Header card ─────────────────────────────────────────────────────
  const sandboxLabel = provenance.staticOnly ? PALETTE.warn("static-only") : PALETTE.safe("sandbox+static");
  const aiLabel = provenance.aiEnabled
    ? PALETTE.accent(`AI: ${provenance.aiProvider}`)
    : PALETTE.muted("AI: deterministic fallback");
  lines.push(
    ...box(
      [
        `${PALETTE.muted("Tested")}      ${chalk.bold(metrics.totalPackagesTested.toString())} packages   ${PALETTE.muted(`(${provenance.datasetSizes.malicious} malicious · ${provenance.datasetSizes.benign} benign)`)}`,
        `${PALETTE.muted("Mode")}        ${sandboxLabel}   ${aiLabel}   ${PALETTE.muted(`husk ${provenance.huskVersion}${provenance.gitSha ? ` · ${provenance.gitSha.slice(0, 7)}${provenance.gitDirty ? "+dirty" : ""}` : ""}`)}`,
        `${PALETTE.muted("Latency")}     p50 ${chalk.bold(fmtMs(metrics.latency.p50))}   p95 ${chalk.bold(fmtMs(metrics.latency.p95))}   p99 ${chalk.bold(fmtMs(metrics.latency.p99))}   ${PALETTE.muted(`· wall ${fmtMs(provenance.durationMs)}`)}`
      ],
      { title: "Husk Benchmark Results", color: PALETTE.border }
    )
  );
  lines.push("");

  // ── Headline metrics with CI ────────────────────────────────────────
  lines.push(`  ${PALETTE.highlight.bold("Headline metrics")}   ${PALETTE.muted("(95% CI in brackets — small samples = wide intervals)")}`);
  const headlineRows: string[][] = [
    [
      "Precision",
      verdictColor(metrics.precision.rate)(chalk.bold(pct(metrics.precision.rate))),
      PALETTE.muted(fmtCi(metrics.precision.ci95)),
      PALETTE.muted(`of ${metrics.precision.total} flagged, ${metrics.truePositives} were truly malicious`)
    ],
    [
      "Recall",
      verdictColor(metrics.recall.rate)(chalk.bold(pct(metrics.recall.rate))),
      PALETTE.muted(fmtCi(metrics.recall.ci95)),
      PALETTE.muted(`caught ${metrics.truePositives} of ${metrics.recall.total} malicious — missed ${metrics.falseNegatives}`)
    ],
    [
      "F1 score",
      verdictColor(metrics.f1)(chalk.bold(pct(metrics.f1))),
      PALETTE.muted(fmtCi(metrics.f1Ci95)),
      PALETTE.muted("harmonic mean (bootstrapped 95% CI)")
    ],
    [
      "FP rate",
      verdictColor(metrics.fpRate.rate, true)(chalk.bold(pct(metrics.fpRate.rate))),
      PALETTE.muted(fmtCi(metrics.fpRate.ci95)),
      PALETTE.muted(`${metrics.falsePositives} of ${metrics.fpRate.total} benign packages mistakenly flagged`)
    ]
  ];
  lines.push(
    ...renderTable(
      [
        { header: "Metric", minWidth: 10 },
        { header: "Value", align: "right", minWidth: 7 },
        { header: "95% CI", align: "right", minWidth: 16 },
        { header: "Notes", maxWidth: 44 }
      ],
      headlineRows,
      { color: PALETTE.border }
    )
  );
  lines.push("");

  // ── Confusion matrix ────────────────────────────────────────────────
  lines.push(`  ${PALETTE.highlight.bold("Confusion matrix")}`);
  lines.push(
    ...renderTable(
      [
        { header: "", minWidth: 22 },
        { header: "Detected as malicious", align: "right", minWidth: 22 },
        { header: "Detected as benign", align: "right", minWidth: 20 }
      ],
      [
        [
          `Malicious ${PALETTE.muted(`(${provenance.datasetSizes.malicious})`)}`,
          PALETTE.safe.bold(`TP ${metrics.truePositives.toString().padStart(3)}`),
          PALETTE.danger.bold(`FN ${metrics.falseNegatives.toString().padStart(3)}`)
        ],
        [
          `Benign    ${PALETTE.muted(`(${provenance.datasetSizes.benign})`)}`,
          PALETTE.danger.bold(`FP ${metrics.falsePositives.toString().padStart(3)}`),
          PALETTE.safe.bold(`TN ${metrics.trueNegatives.toString().padStart(3)}`)
        ]
      ],
      { color: PALETTE.border }
    )
  );
  lines.push("");

  // ── Baselines ───────────────────────────────────────────────────────
  lines.push(`  ${PALETTE.highlight.bold("Baseline comparison")}   ${PALETTE.muted("(does Husk add signal over trivial heuristics?)")}`);
  const huskRow = [
    PALETTE.accent.bold("Husk"),
    PALETTE.accent.bold(pct(metrics.precision.rate)),
    PALETTE.accent.bold(pct(metrics.recall.rate)),
    PALETTE.accent.bold(pct(metrics.f1)),
    PALETTE.accent.bold(pct(metrics.fpRate.rate))
  ];
  const baselineRows = baselines.map((b) => [
    b.name,
    PALETTE.muted(pct(b.precision)),
    PALETTE.muted(pct(b.recall)),
    PALETTE.muted(pct(b.f1)),
    PALETTE.muted(pct(b.fpRate))
  ]);
  lines.push(
    ...renderTable(
      [
        { header: "Method", minWidth: 20 },
        { header: "Precision", align: "right", minWidth: 10 },
        { header: "Recall", align: "right", minWidth: 8 },
        { header: "F1", align: "right", minWidth: 8 },
        { header: "FP rate", align: "right", minWidth: 8 }
      ],
      [huskRow, ...baselineRows],
      { color: PALETTE.border }
    )
  );
  lines.push("");

  // ── Per-category recall with CI ─────────────────────────────────────
  if (metrics.categoryRates.length > 0) {
    lines.push(`  ${PALETTE.highlight.bold("Detection by category")}`);
    const rows = metrics.categoryRates
      .slice()
      .sort((a, b) => b.total - a.total)
      .map((entry) => [
        entry.category,
        `${entry.detected}/${entry.total}`,
        verdictColor(entry.rate)(chalk.bold(pct(entry.rate))),
        PALETTE.muted(entry.total < 5 ? `n=${entry.total} — too small to trust` : fmtCi(entry.ci95))
      ]);
    lines.push(
      ...renderTable(
        [
          { header: "Category", minWidth: 22, maxWidth: 36 },
          { header: "Detected", align: "right", minWidth: 10 },
          { header: "Rate", align: "right", minWidth: 8 },
          { header: "95% CI", align: "right", minWidth: 22 }
        ],
        rows,
        { color: PALETTE.border }
      )
    );
    lines.push("");
  }

  // ── Top false positives ─────────────────────────────────────────────
  if (topFP.length > 0) {
    lines.push(`  ${PALETTE.highlight.bold("Top false positives")}   ${PALETTE.muted("(benign packages Husk wrongly flagged)")}`);
    lines.push(
      ...renderTable(
        [
          { header: "Package", minWidth: 16, maxWidth: 24 },
          { header: "Conf", align: "right", minWidth: 5 },
          { header: "Top reason", maxWidth: 18 },
          { header: "Evidence", maxWidth: 36 }
        ],
        topFP.map((r) => [
          PALETTE.danger(r.name),
          `${Math.round(r.confidence * 100)}%`,
          r.topReasonTitle ?? PALETTE.muted("—"),
          PALETTE.muted(truncate(r.topReasonEvidence ?? "", 200))
        ]),
        { color: PALETTE.border }
      )
    );
    lines.push("");
  }

  // ── Top false negatives ─────────────────────────────────────────────
  if (topFN.length > 0) {
    lines.push(`  ${PALETTE.highlight.bold("Top false negatives")}   ${PALETTE.muted("(known malicious packages Husk missed)")}`);
    lines.push(
      ...renderTable(
        [
          { header: "Package", minWidth: 16, maxWidth: 28 },
          { header: "Category", minWidth: 16, maxWidth: 22 },
          { header: "Conf", align: "right", minWidth: 5 },
          { header: "Best reason found", maxWidth: 32 }
        ],
        topFN.map((r) => [
          PALETTE.danger(r.name),
          PALETTE.muted(r.category ?? "—"),
          `${Math.round(r.confidence * 100)}%`,
          PALETTE.muted(truncate(r.topReasonTitle ?? "(no detector fired)", 200))
        ]),
        { color: PALETTE.border }
      )
    );
    lines.push("");
  }

  // ── Credibility warnings ────────────────────────────────────────────
  lines.push(`  ${PALETTE.highlight.bold("Credibility caveats")}   ${PALETTE.muted("(read before quoting these numbers)")}`);
  const caveats: string[] = [];
  if (leakage.allowlistShareOfBenign > 0) {
    caveats.push(
      `${PALETTE.danger("●")} Data leakage: ${leakage.benignOnAllowlist}/${leakage.benignTotal} (${pct(leakage.allowlistShareOfBenign)}) of benign samples are on Husk's internal popular-packages allowlist, which short-circuits the typosquat detector. The FP rate is therefore an optimistic lower bound.`
    );
  }
  if (provenance.staticOnly) {
    caveats.push(
      `${PALETTE.warn("●")} Sandbox disabled (staticOnly=true): the dynamic-analysis subsystem was not exercised. Recall on novel attacks is likely lower.`
    );
  }
  if (provenance.datasetSizes.malicious < 100) {
    caveats.push(
      `${PALETTE.warn("●")} Small sample (${provenance.datasetSizes.malicious} malicious / ${provenance.datasetSizes.benign} benign). Confidence intervals reflect this — point estimates can move ±10pp between runs.`
    );
  }
  if (metrics.recall.rate < 0.7) {
    caveats.push(
      `${PALETTE.danger("●")} Recall is ${pct(metrics.recall.rate)} on KNOWN historical malware. Against truly novel attacks (no prior IOC, no behavior baseline, not on a popular-package list), recall is expected to be substantially lower.`
    );
  }
  if (provenance.aiEnabled) {
    caveats.push(
      `${PALETTE.muted("●")} AI verdict agent is enabled (${provenance.aiProvider}). Results are not deterministic between runs unless responses are cached.`
    );
  }
  if (!provenance.gitSha) {
    caveats.push(
      `${PALETTE.muted("●")} No git SHA recorded (not a git repo or git unavailable). Can't tie this run to a code revision.`
    );
  }
  for (const c of caveats) lines.push(`    ${c}`);
  lines.push("");

  // ── Footer ──────────────────────────────────────────────────────────
  if (ctx.artifactsDir) {
    lines.push(
      `  ${PALETTE.muted("Full per-package results, FP/FN evidence, baselines, and provenance →")} ${PALETTE.accent(ctx.artifactsDir)}`
    );
  }

  return lines.join("\n");
}

// ─── Markdown report (for the on-disk file) ────────────────────────────────

export function generateMarkdownReport(ctx: TerminalReportContext): string {
  const { metrics, leakage, baselines, provenance, topFP, topFN } = ctx;
  const md: string[] = [];

  md.push("# Husk Benchmark Results");
  md.push("");
  md.push(`_Run at ${provenance.timestamp} · husk ${provenance.huskVersion}${provenance.gitSha ? ` (${provenance.gitSha.slice(0, 7)}${provenance.gitDirty ? "+dirty" : ""})` : ""} · node ${provenance.nodeVersion} · ${provenance.platform}/${provenance.arch}_`);
  md.push("");

  md.push("## Summary");
  md.push("");
  md.push("| Metric | Value | 95% CI |");
  md.push("|---|---|---|");
  md.push(`| **Precision** | **${pct(metrics.precision.rate)}** | ${fmtCi(metrics.precision.ci95)} |`);
  md.push(`| **Recall** | **${pct(metrics.recall.rate)}** | ${fmtCi(metrics.recall.ci95)} |`);
  md.push(`| **F1** | **${pct(metrics.f1)}** | ${fmtCi(metrics.f1Ci95)} (bootstrap, 1000 it) |`);
  md.push(`| **FP rate** | **${pct(metrics.fpRate.rate)}** | ${fmtCi(metrics.fpRate.ci95)} |`);
  md.push(`| TP / FP / TN / FN | ${metrics.truePositives} / ${metrics.falsePositives} / ${metrics.trueNegatives} / ${metrics.falseNegatives} | |`);
  md.push(`| Latency p50/p95/p99 | ${fmtMs(metrics.latency.p50)} / ${fmtMs(metrics.latency.p95)} / ${fmtMs(metrics.latency.p99)} | |`);
  md.push("");

  md.push("## Baseline comparison");
  md.push("");
  md.push("| Method | Precision | Recall | F1 | FP rate |");
  md.push("|---|---|---|---|---|");
  md.push(`| **Husk** | **${pct(metrics.precision.rate)}** | **${pct(metrics.recall.rate)}** | **${pct(metrics.f1)}** | **${pct(metrics.fpRate.rate)}** |`);
  for (const b of baselines) {
    md.push(`| ${b.name} | ${pct(b.precision)} | ${pct(b.recall)} | ${pct(b.f1)} | ${pct(b.fpRate)} |`);
  }
  md.push("");

  if (metrics.categoryRates.length > 0) {
    md.push("## Detection by category");
    md.push("");
    md.push("| Category | Detected | Total | Rate | 95% CI |");
    md.push("|---|---|---|---|---|");
    for (const c of metrics.categoryRates.slice().sort((a, b) => b.total - a.total)) {
      md.push(`| ${c.category} | ${c.detected} | ${c.total} | ${pct(c.rate)} | ${c.total < 5 ? `n=${c.total} (untrustworthy)` : fmtCi(c.ci95)} |`);
    }
    md.push("");
  }

  if (topFP.length > 0) {
    md.push("## Top false positives");
    md.push("");
    md.push("| Package | Confidence | Top reason | Evidence |");
    md.push("|---|---|---|---|");
    for (const r of topFP) {
      md.push(`| \`${r.name}\` | ${Math.round(r.confidence * 100)}% | ${r.topReasonTitle ?? "—"} | ${truncate(r.topReasonEvidence ?? "", 240)} |`);
    }
    md.push("");
  }

  if (topFN.length > 0) {
    md.push("## Top false negatives");
    md.push("");
    md.push("| Package | Category | Confidence | Best reason found |");
    md.push("|---|---|---|---|");
    for (const r of topFN) {
      md.push(`| \`${r.name}\` | ${r.category ?? "—"} | ${Math.round(r.confidence * 100)}% | ${truncate(r.topReasonTitle ?? "(no detector fired)", 240)} |`);
    }
    md.push("");
  }

  md.push("## Credibility caveats");
  md.push("");
  if (leakage.allowlistShareOfBenign > 0) {
    md.push(`- **Data leakage**: ${leakage.benignOnAllowlist}/${leakage.benignTotal} (${pct(leakage.allowlistShareOfBenign)}) of benign samples are on Husk's internal popular-packages allowlist, which short-circuits the typosquat detector. The FP rate is an optimistic lower bound.`);
  }
  if (provenance.staticOnly) {
    md.push(`- **Sandbox disabled** (\`staticOnly=true\`): the dynamic-analysis subsystem was not exercised. Recall on novel attacks is likely lower than measured here.`);
  }
  if (provenance.datasetSizes.malicious < 100) {
    md.push(`- **Small sample** (${provenance.datasetSizes.malicious} malicious / ${provenance.datasetSizes.benign} benign). Point estimates can move ±10pp between runs; trust the CIs.`);
  }
  if (metrics.recall.rate < 0.7) {
    md.push(`- **Recall on novel attacks**: ${pct(metrics.recall.rate)} is measured on KNOWN historical malware that Husk's rules were partly tuned on. Against truly novel attacks (no prior IOC, no behavior baseline, not on a popular-package list), recall is expected to be substantially lower.`);
  }
  if (provenance.aiEnabled) {
    md.push(`- **Non-determinism**: AI verdict agent (${provenance.aiProvider}) is enabled. Results vary between runs unless responses are cached.`);
  }
  md.push("");

  md.push("## Provenance");
  md.push("");
  md.push("```json");
  md.push(JSON.stringify(provenance, null, 2));
  md.push("```");

  return md.join("\n");
}
