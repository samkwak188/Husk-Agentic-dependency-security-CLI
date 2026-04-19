#!/usr/bin/env node
// Loads .env from the project root (NOT from cwd), so OPENROUTER_API_KEY /
// OPENAI_API_KEY are picked up regardless of which directory the user
// invokes `husk` from. Must be the first import so subsequent module
// evaluation sees the env vars before reading them.
import "../core/project-root.js";

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import chalk from "chalk";
import { Command } from "commander";
import ora from "ora";

import { HuskOrchestrator } from "../agents/orchestrator.js";
import { RegistryError } from "../core/registry.js";
import type { HuskVerdict, PolicyAction, ScanEvent } from "../core/types.js";
import { formatEvidence } from "./format-evidence.js";
import { executeGuardedInstall, planGuardedInstall, type GuardedInstallPlan, type InstallManager } from "./guarded-install.js";
import {
  DEFAULT_PORT,
  disableIntercept,
  enableIntercept,
  getInterceptLogPath,
  getInterceptStatus,
  readInterceptLog
} from "./intercept.js";
import {
  box,
  padVisible,
  pickPhrase,
  printBox,
  renderTable,
  truncateVisible,
  visibleWidth
} from "./ui.js";

const PROJECT_ROOT = fileURLToPath(new URL("../..", import.meta.url));

// Reactive Husk spinner — combines a 6-frame asterisk spinner (Claude-Code style)
// with stage-aware status text and a rotating whimsical phrase.
const HUSK_SPINNER = {
  interval: 110,
  frames: ["·", "✢", "✳", "✶", "✻", "✽"]
};

const STAGE_LABEL: Record<string, string> = {
  fetch: "Fetching package",
  triage: "Triaging risk",
  static: "Static analysis",
  sandbox: "Sandbox running in Docker",
  verdict: "Computing verdict",
  narrative: "Drafting narrative",
  policy: "Applying policy",
  report: "Generating advisory",
  action: "Drafting next step"
};

function createHuskSpinner(packageSpec: string) {
  const spinner = ora({
    text: chalk.dim(`Sniffing ${packageSpec}`),
    spinner: HUSK_SPINNER,
    color: "cyan"
  }).start();

  const startedAt = Date.now();
  let currentStage = "fetch";
  let currentMessage = STAGE_LABEL.fetch;
  let phraseSeed = Date.now();

  const render = () => {
    const elapsed = Math.floor((Date.now() - startedAt) / 1000);
    const elapsedTag = elapsed > 0 ? chalk.dim(` ${elapsed}s`) : "";
    const phrase = chalk.italic.dim(pickPhrase(phraseSeed / 2200));
    spinner.text = `${chalk.bold(packageSpec)} ${chalk.dim("·")} ${currentMessage} ${chalk.dim("·")} ${phrase}${elapsedTag}`;
  };

  const ticker = setInterval(() => {
    phraseSeed += 1;
    render();
  }, 2200);

  const onEvent = (event: ScanEvent) => {
    if (event.type === "scan:progress" && event.payload) {
      currentStage = String(event.payload.stage ?? "");
      currentMessage = String(event.payload.message ?? STAGE_LABEL[currentStage] ?? "Working");
      render();
    }
  };

  const stop = () => {
    clearInterval(ticker);
    spinner.stop();
  };

  const succeed = (reason?: string) => {
    clearInterval(ticker);
    spinner.succeed(chalk.green(reason ?? `${packageSpec} scanned in ${formatDuration(Date.now() - startedAt)}`));
  };

  const fail = (reason: string) => {
    clearInterval(ticker);
    spinner.fail(chalk.red(reason));
  };

  return { onEvent, stop, succeed, fail };
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 10_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 1000)}s`;
}

function formatStageTimings(stageTimings?: Record<string, number>): string | null {
  if (!stageTimings) {
    return null;
  }

  const order = ["fetch", "triage", "static", "sandbox", "verdict", "narrative", "policy", "report"];
  const parts = order
    .filter((stage) => typeof stageTimings[stage] === "number")
    .map((stage) => `${(STAGE_LABEL[stage] ?? stage).toLowerCase()} ${formatDuration(stageTimings[stage])}`);

  return parts.length ? parts.join("  ·  ") : null;
}

function printBanner(): void {
  if (!process.stdout.isTTY || process.argv.includes("--json")) {
    return;
  }

  const banner = [
    "  ██╗  ██╗██╗   ██╗███████╗██╗  ██╗",
    "  ██║  ██║██║   ██║██╔════╝██║ ██╔╝",
    "  ███████║██║   ██║███████╗█████╔╝ ",
    "  ██╔══██║██║   ██║╚════██║██╔═██╗ ",
    "  ██║  ██║╚██████╔╝███████║██║  ██╗",
    "  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝"
  ];

  for (const line of banner) {
    console.log(chalk.hex("#00d18f")(line));
  }
  console.log(`${chalk.dim("  ")}${chalk.hex("#7dd3fc")("agentic supply-chain dependency gate")} ${chalk.dim("·")} ${chalk.dim("v0.1.0")}\n`);
}

function printWelcome(): void {
  printBanner();

  if (!process.stdout.isTTY) {
    return;
  }

  const rows: Array<[string, string]> = [
    ["scan <package>",          "Analyze a package without installing"],
    ["decide <mgr> <pkgs...>",  "Get an ALLOW / WARN / BLOCK decision"],
    ["install <mgr> <pkgs...>", "Install only after Husk approves"],
    ["intercept --enable",      "Transparently scan every npm install"],
    ["dashboard",               "Live web UI at http://localhost:3000"],
    ["benchmark",               "Run the malware-detection evaluation"]
  ];
  const colWidth = Math.max(...rows.map((row) => row[0].length)) + 2;

  console.log(PALETTE.highlight.bold("  COMMANDS"));
  for (const [command, description] of rows) {
    console.log(`    ${PALETTE.command.bold(command.padEnd(colWidth))}${PALETTE.muted(description)}`);
  }

  console.log("");
  console.log(PALETTE.highlight.bold("  EXAMPLES"));
  console.log(`    ${PALETTE.muted("$")} ${PALETTE.accent("husk scan express@4.19.2 --sandbox")}`);
  console.log(`    ${PALETTE.muted("$")} ${PALETTE.accent("husk install npm react@18.2.0")}`);
  console.log(`    ${PALETTE.muted("$")} ${PALETTE.accent("husk dashboard")}`);
  console.log("");
  console.log(PALETTE.muted(`  Run 'husk <command> --help' for command-specific options.`));
  console.log("");
}

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const SEVERITY_GLYPH: Record<Severity, string> = {
  CRITICAL: "✖",
  HIGH: "▲",
  MEDIUM: "●",
  LOW: "·"
};

function colorVerdict(verdict: HuskVerdict["verdict"]): (text: string) => string {
  if (verdict === "MALICIOUS") return chalk.red.bold;
  if (verdict === "SUSPICIOUS") return chalk.yellow.bold;
  return chalk.green.bold;
}

function colorPolicy(action: PolicyAction): (text: string) => string {
  if (action === "BLOCK") return chalk.red.bold;
  if (action === "WARN") return chalk.yellow.bold;
  return chalk.green.bold;
}

function colorSeverity(severity: Severity): (text: string) => string {
  if (severity === "CRITICAL") return chalk.red.bold;
  if (severity === "HIGH") return chalk.red;
  if (severity === "MEDIUM") return chalk.yellow;
  return chalk.dim;
}

function renderVerdict(verdict: HuskVerdict): string {
  return colorVerdict(verdict.verdict)(verdict.verdict);
}

function renderPolicyAction(action: PolicyAction): string {
  return colorPolicy(action)(action);
}

function wrapText(text: string, width: number, indent: string): string {
  if (text.length <= width) {
    return text;
  }

  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";

  for (const word of words) {
    if (!current.length) {
      current = word;
      continue;
    }

    if (current.length + 1 + word.length > width) {
      lines.push(current);
      current = word;
      continue;
    }

    current = `${current} ${word}`;
  }

  if (current.length) {
    lines.push(current);
  }

  return lines.join(`\n${indent}`);
}

function printSectionHeader(label: string): void {
  console.log(chalk.dim(label));
}

type Headline = "SAFE TO INSTALL" | "BE CAREFUL" | "DO NOT INSTALL";

function deriveHeadline(verdict: HuskVerdict): Headline {
  if (verdict.userAction?.headline) return verdict.userAction.headline;
  if (verdict.verdict === "MALICIOUS" || verdict.policy.action === "BLOCK") return "DO NOT INSTALL";
  if (verdict.verdict === "SUSPICIOUS" || verdict.policy.action === "WARN") return "BE CAREFUL";
  return "SAFE TO INSTALL";
}

// Color palette — semantic, consistent, and high-contrast against dark terminals.
const PALETTE = {
  safe: chalk.hex("#22c55e"),
  warn: chalk.hex("#f59e0b"),
  danger: chalk.hex("#ef4444"),
  accent: chalk.hex("#7dd3fc"),
  highlight: chalk.hex("#a78bfa"),
  muted: chalk.hex("#94a3b8"),
  command: chalk.hex("#38bdf8"),
  brand: chalk.hex("#00d18f")
};

function headlineStyle(headline: Headline): { color: (text: string) => string; bold: (text: string) => string; glyph: string; label: string } {
  if (headline === "DO NOT INSTALL") {
    return { color: PALETTE.danger, bold: PALETTE.danger.bold, glyph: "✗", label: "BLOCKED" };
  }
  if (headline === "BE CAREFUL") {
    return { color: PALETTE.warn, bold: PALETTE.warn.bold, glyph: "⚠", label: "REVIEW" };
  }
  return { color: PALETTE.safe, bold: PALETTE.safe.bold, glyph: "✓", label: "SAFE" };
}

const CARD_WIDTH = 78;

function printVerdictCard(verdict: HuskVerdict): void {
  const headline = deriveHeadline(verdict);
  const { color, bold, glyph } = headlineStyle(headline);

  const headerLeft = `${color(glyph)}  ${bold(headline)}`;
  const headerRight = `${PALETTE.muted(verdict.ecosystem)} ${PALETTE.muted("·")} ${PALETTE.accent(`${verdict.packageName}@${verdict.packageVersion}`)}`;

  const innerWidth = CARD_WIDTH - 2 - 4;
  const headerLine = padVisible(
    headerLeft + " ".repeat(Math.max(2, innerWidth - visibleWidth(headerLeft) - visibleWidth(headerRight))) + headerRight,
    innerWidth
  );

  const action = verdict.userAction;
  const lines: string[] = [];
  lines.push(headerLine);
  lines.push("");
  if (action) {
    lines.push(PALETTE.highlight.bold("What it is"));
    lines.push(action.what_it_does);
    lines.push("");
    lines.push(PALETTE.highlight.bold("Why this verdict"));
    lines.push(action.why);
    lines.push("");
    lines.push(PALETTE.highlight.bold("What to do"));
    lines.push(`${color("→")} ${action.next_step}`);
    if (action.command) {
      lines.push(`${PALETTE.muted("$")} ${PALETTE.command.bold(action.command)}`);
    }
  } else if (verdict.recommendations.length) {
    lines.push(PALETTE.highlight.bold("What to do"));
    for (const recommendation of verdict.recommendations.slice(0, 3)) {
      lines.push(`${color("→")} ${recommendation}`);
    }
  }

  console.log("");
  for (const line of box(lines, { color, width: CARD_WIDTH, padX: 2 })) {
    console.log(line);
  }
}

function findClosestVersions(target: string | undefined, available: string[] | undefined): string[] {
  if (!available?.length) return [];
  if (!target) return available.slice(-3);
  // Prefer same-major neighbors, otherwise the latest 3.
  try {
    const major = target.split(".")[0];
    const sameMajor = available.filter((v) => v.startsWith(`${major}.`));
    const pool = sameMajor.length ? sameMajor : available;
    return pool.slice(-3);
  } catch {
    return available.slice(-3);
  }
}

/**
 * Render a registry-resolution failure as a real verdict-style card.
 * For Husk, an unpublished version / security placeholder is *itself* a
 * malicious-package signal — the registry already took action.
 */
function printRegistryError(error: RegistryError): void {
  const target = error.requestedVersion ? `${error.packageName}@${error.requestedVersion}` : error.packageName;

  // Classify: is this a security-relevant unpublish, or a benign typo?
  const isSecuritySignal =
    error.code === "unpublished-version" ||
    error.code === "unpublished-package" ||
    error.code === "security-placeholder";

  const palette = isSecuritySignal ? PALETTE.danger : PALETTE.warn;
  const glyph = isSecuritySignal ? "✗" : "?";
  const label = isSecuritySignal ? "REMOVED BY REGISTRY" : "PACKAGE NOT FOUND";

  const headerLeft = `${palette(glyph)}  ${palette.bold(label)}`;
  const headerRight = `${PALETTE.muted(error.ecosystem)} ${PALETTE.muted("·")} ${PALETTE.accent(target)}`;
  const innerWidth = CARD_WIDTH - 2 - 4;
  const headerLine = padVisible(
    headerLeft + " ".repeat(Math.max(2, innerWidth - visibleWidth(headerLeft) - visibleWidth(headerRight))) + headerRight,
    innerWidth
  );

  const lines: string[] = [];
  lines.push(headerLine);
  lines.push("");

  lines.push(PALETTE.highlight.bold("What happened"));
  switch (error.code) {
    case "unpublished-version":
      lines.push(`The ${error.ecosystem} registry no longer serves ${target}.`);
      lines.push(`This version was published${error.publishedAt ? ` on ${error.publishedAt.slice(0, 10)}` : ""} and later unpublished.`);
      break;
    case "unpublished-package":
      lines.push(`${error.packageName} was fully unpublished from the ${error.ecosystem} registry${error.unpublishedAt ? ` on ${error.unpublishedAt.slice(0, 10)}` : ""}.`);
      break;
    case "security-placeholder":
      lines.push(`${error.packageName} was taken down and replaced by npm with a security advisory placeholder (${error.latest}).`);
      break;
    case "unknown-package":
      lines.push(`${error.packageName} does not exist in the ${error.ecosystem} registry.`);
      break;
    case "unknown-version":
      lines.push(`${target} was never published — only the versions below have ever existed.`);
      break;
    case "no-default-version":
      lines.push(`${error.packageName} has no \"latest\" tag. Pin a version to scan it.`);
      break;
    case "fetch-failed":
      lines.push(`Could not reach the ${error.ecosystem} registry. ${error.message}`);
      break;
  }
  lines.push("");

  lines.push(PALETTE.highlight.bold("Why this matters"));
  if (isSecuritySignal) {
    lines.push("Registries unpublish versions when they are confirmed malicious,");
    lines.push("compromised, or otherwise harmful. Treat this as a strong signal that");
    lines.push("the version you asked for was bad — the registry already pulled it.");
  } else if (error.code === "unknown-package") {
    lines.push("This name does not exist on the registry. If you typed it from memory,");
    lines.push("double-check the spelling — typosquats often live one keystroke away");
    lines.push("from a real package.");
  } else if (error.code === "unknown-version") {
    lines.push("Either the version number is wrong, or the maintainer never released");
    lines.push("it. Pin one of the versions below.");
  }
  lines.push("");

  lines.push(PALETTE.highlight.bold("What to do"));
  if (error.code === "security-placeholder") {
    lines.push(`${palette("→")} Do not install ${PALETTE.accent(error.packageName)}. The current package is just a takedown stub.`);
    lines.push(`${palette("→")} If you meant a similar name, verify the canonical spelling on the registry first.`);
  } else if (isSecuritySignal && error.latest && !/-security$/.test(error.latest)) {
    lines.push(`${palette("→")} Use the registry's current ${PALETTE.accent("latest")} version: ${PALETTE.accent(error.latest)}`);
    lines.push(`${PALETTE.muted("$")} ${PALETTE.command.bold(`husk scan ${error.packageName}@${error.latest} --sandbox`)}`);
  } else {
    const suggestions = findClosestVersions(error.requestedVersion, error.availableVersions);
    if (suggestions.length) {
      lines.push(`${palette("→")} Try one of these published versions: ${PALETTE.accent(suggestions.join(", "))}`);
      lines.push(`${PALETTE.muted("$")} ${PALETTE.command.bold(`husk scan ${error.packageName}@${suggestions[suggestions.length - 1]}`)}`);
    } else {
      lines.push(`${palette("→")} Verify the package name on the registry website before installing anything similar.`);
    }
  }

  console.log("");
  for (const line of box(lines, { color: palette, width: CARD_WIDTH, padX: 2 })) {
    console.log(line);
  }

  // Footer
  const footer = [
    `${PALETTE.muted("registry")} ${palette(error.code)}`,
    `${PALETTE.muted("ecosystem")} ${PALETTE.accent(error.ecosystem)}`
  ];
  if (error.availableVersions?.length) {
    footer.push(`${PALETTE.muted("known versions")} ${PALETTE.accent(String(error.availableVersions.length))}`);
  }
  console.log("");
  console.log(`  ${footer.join(PALETTE.muted("  ·  "))}`);
  console.log("");
}

async function printVerdict(verdict: HuskVerdict, options: { verbose?: boolean } = {}): Promise<void> {
  printVerdictCard(verdict);

  if (verdict.reasons.length) {
    const visible = options.verbose ? verdict.reasons : verdict.reasons.slice(0, 5);
    const formattedEvidence = await Promise.all(
      visible.map((reason) => formatEvidence(reason, { useAI: true }))
    );
    const rows = visible.map((reason, index) => [
      colorSeverity(reason.severity as Severity)(reason.severity),
      chalk.bold(reason.title),
      PALETTE.muted(formattedEvidence[index])
    ]);
    console.log("");
    for (const line of renderTable(
      [
        { header: "Severity", minWidth: 8 },
        { header: "Finding", minWidth: 20, maxWidth: 28 },
        { header: "Evidence", minWidth: 30, maxWidth: 56 }
      ],
      rows,
      { color: PALETTE.muted }
    )) {
      console.log(`  ${line}`);
    }
    const hidden = verdict.reasons.length - visible.length;
    if (hidden > 0) {
      console.log(PALETTE.muted(`    … +${hidden} more findings (run with --verbose or --json)`));
    }
  }

  const footerParts = [
    `${PALETTE.muted("verdict")} ${headlineStyle(deriveHeadline(verdict)).color(verdict.verdict.toLowerCase())}`,
    `${PALETTE.muted("policy")} ${headlineStyle(deriveHeadline(verdict)).color(verdict.policy.action.toLowerCase())}`,
    `${PALETTE.muted("confidence")} ${PALETTE.accent(Math.round(verdict.confidence * 100) + "%")}`,
    `${PALETTE.muted("scan")} ${PALETTE.accent(formatDuration(verdict.scanDuration))}`
  ];
  console.log("");
  console.log(`  ${footerParts.join(PALETTE.muted("  ·  "))}`);
  if (options.verbose) {
    const breakdown = formatStageTimings(verdict.stageTimings);
    if (breakdown) console.log(`  ${PALETTE.muted(breakdown)}`);
  }
  console.log("");
}

async function printInstallPlan(plan: GuardedInstallPlan): Promise<void> {
  const palette = plan.overallAction === "BLOCK" ? PALETTE.danger : plan.overallAction === "WARN" ? PALETTE.warn : PALETTE.safe;
  const summaryGlyph = plan.overallAction === "BLOCK" ? "✗" : plan.overallAction === "WARN" ? "⚠" : "✓";
  const allowedCount = plan.verdicts.length - plan.blocked.length - plan.warnings.length;

  console.log("");
  printBox(
    [
      `${palette(summaryGlyph)}  ${palette.bold(`Install decision: ${plan.overallAction}`)}`,
      "",
      `${PALETTE.muted("Command")}    ${PALETTE.command.bold(plan.installCommand.display)}`,
      `${PALETTE.muted("Packages")}   ${chalk.bold(String(plan.verdicts.length))}    ${PALETTE.safe(`✓ ${allowedCount} allow`)}    ${PALETTE.warn(`⚠ ${plan.warnings.length} warn`)}    ${PALETTE.danger(`✗ ${plan.blocked.length} block`)}`
    ],
    { color: palette, width: CARD_WIDTH }
  );

  if (plan.verdicts.length > 1) {
    const rows = plan.verdicts.map((verdict) => {
      const action = verdict.policy.action;
      const headline = deriveHeadline(verdict);
      const { color, bold, glyph } = headlineStyle(headline);
      return [
        PALETTE.accent(`${verdict.packageName}@${verdict.packageVersion}`),
        `${color(glyph)} ${bold(action)}`,
        PALETTE.muted(truncateVisible(verdict.userAction?.next_step ?? verdict.recommendations[0] ?? "", 50))
      ];
    });
    console.log("");
    for (const line of renderTable(
      [
        { header: "Package", minWidth: 22 },
        { header: "Action", minWidth: 10 },
        { header: "What to do", minWidth: 30 }
      ],
      rows,
      { color: PALETTE.muted }
    )) {
      console.log(`  ${line}`);
    }
  }

  for (const verdict of plan.verdicts) {
    await printVerdict(verdict);
  }
}

function printWorkflowWarnings(verdict: HuskVerdict): void {
  const stageEntries = [
    ["triage", verdict.workflow.triage],
    ["dynamic narration", verdict.workflow.dynamicNarration],
    ["reporting", verdict.workflow.reporting]
  ] as const;

  for (const [label, stage] of stageEntries) {
    if (!stage.error) {
      continue;
    }

    const details = [stage.error.code ?? stage.error.type, stage.error.status ? `HTTP ${stage.error.status}` : null, stage.error.message]
      .filter(Boolean)
      .join(" | ");
    const providerLabel = stage.provider === "openrouter" ? "OpenRouter" : stage.provider === "openai" ? "OpenAI" : "AI";
    console.warn(chalk.dim(`  note: ${providerLabel} fallback on ${label} (${details})`));
  }
}

async function scanPackage(packageSpec: string, options: { local?: string; json?: boolean; sandbox?: boolean; staticOnly?: boolean; ecosystem?: "npm" | "pypi"; verbose?: boolean }) {
  const spinner = createHuskSpinner(packageSpec);
  try {
    const orchestrator = new HuskOrchestrator();
    const verdict = await orchestrator.analyze(packageSpec, {
      localPath: options.local,
      ecosystem: options.ecosystem,
      forceSandbox: options.sandbox,
      staticOnly: options.staticOnly,
      emitEvent: spinner.onEvent
    });
    spinner.stop();

    if (options.json) {
      console.log(JSON.stringify(verdict, null, 2));
      return;
    }

    await printVerdict(verdict, { verbose: options.verbose });
    printWorkflowWarnings(verdict);
  } catch (error) {
    if (error instanceof RegistryError) {
      spinner.stop();
      if (options.json) {
        console.log(JSON.stringify({
          error: {
            code: error.code,
            message: error.message,
            packageName: error.packageName,
            requestedVersion: error.requestedVersion,
            latest: error.latest,
            unpublishedAt: error.unpublishedAt,
            publishedAt: error.publishedAt,
            availableVersions: error.availableVersions
          }
        }, null, 2));
      } else {
        printRegistryError(error);
      }
      const isSecuritySignal =
        error.code === "unpublished-version" ||
        error.code === "unpublished-package" ||
        error.code === "security-placeholder";
      // Match install/decide: takedowns are a hard BLOCK (40); typos/missing
      // names are exit 0 (informational); transport problems are exit 1.
      if (isSecuritySignal) {
        process.exitCode = 40;
      } else if (error.code === "fetch-failed" || error.code === "no-default-version") {
        process.exitCode = 1;
      } else {
        process.exitCode = 0;
      }
      return;
    }
    spinner.fail(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

async function scanManifestFile(path: string, options: { json?: boolean; sandbox?: boolean; staticOnly?: boolean; verbose?: boolean }) {
  const manifest = JSON.parse(await readFile(resolve(path), "utf8")) as {
    dependencies?: Record<string, string>;
  };
  const dependencies = manifest.dependencies ?? {};
  const orchestrator = new HuskOrchestrator();
  const results: HuskVerdict[] = [];

  for (const [name, version] of Object.entries(dependencies)) {
    const packageSpec = `${name}@${version}`;
    const spinner = createHuskSpinner(packageSpec);
    try {
      const verdict = await orchestrator.analyze(packageSpec, {
        forceSandbox: options.sandbox,
        staticOnly: options.staticOnly,
        emitEvent: spinner.onEvent
      });
      spinner.stop();
      results.push(verdict);
    } catch (error) {
      if (error instanceof RegistryError) {
        spinner.stop();
        printRegistryError(error);
      } else {
        spinner.fail(error instanceof Error ? error.message : String(error));
      }
    }
  }

  if (options.json) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  for (const verdict of results) {
    await printVerdict(verdict);
  }
}

function assertInstallManager(value: string): InstallManager {
  if (value === "npm" || value === "pip") {
    return value;
  }

  throw new Error(`Unsupported install manager '${value}'. Use 'npm' or 'pip'.`);
}

async function decidePackages(
  manager: InstallManager,
  packageSpecs: string[],
  options: { json?: boolean; sandbox?: boolean; staticOnly?: boolean }
): Promise<GuardedInstallPlan> {
  type HuskSpinner = ReturnType<typeof createHuskSpinner>;
  const spinnerRef: { current: HuskSpinner | null } = { current: null };
  try {
    const plan = await planGuardedInstall(manager, packageSpecs, {
      sandbox: options.sandbox,
      staticOnly: options.staticOnly,
      onPackageStart: (spec) => {
        const next = createHuskSpinner(spec);
        spinnerRef.current = next;
        return next.onEvent;
      },
      onPackageEnd: () => {
        spinnerRef.current?.stop();
        spinnerRef.current = null;
      }
    });

    if (options.json) {
      console.log(JSON.stringify(plan, null, 2));
    } else {
      await printInstallPlan(plan);
      for (const verdict of plan.verdicts) {
        printWorkflowWarnings(verdict);
      }
    }

    return plan;
  } catch (error) {
    if (error instanceof RegistryError) {
      spinnerRef.current?.stop();
      printRegistryError(error);
    } else {
      spinnerRef.current?.fail(error instanceof Error ? error.message : String(error));
    }
    throw error;
  }
}

async function installPackages(
  manager: InstallManager,
  packageSpecs: string[],
  options: { json?: boolean; sandbox?: boolean; staticOnly?: boolean; yes?: boolean; force?: boolean; dryRun?: boolean }
): Promise<void> {
  const plan = await decidePackages(manager, packageSpecs, {
    json: false,
    sandbox: options.sandbox,
    staticOnly: options.staticOnly
  });

  if (options.json) {
    console.log(JSON.stringify(plan, null, 2));
    return;
  }

  const exitCode = await executeGuardedInstall(plan, {
    sandbox: options.sandbox,
    staticOnly: options.staticOnly,
    yes: options.yes,
    force: options.force,
    dryRun: options.dryRun
  });

  if (exitCode === 40) {
    console.error("");
    console.error(chalk.red.bold("  ✖ Install blocked by Husk policy."));
    console.error(chalk.dim("    Re-run with --force only after manually reviewing the package."));
    process.exitCode = 40;
    return;
  }

  if (exitCode === 20) {
    console.error("");
    console.error(chalk.yellow.bold("  ◷ Install cancelled."));
    console.error(chalk.dim("    Husk requires manual confirmation for WARN packages. Pass --yes to auto-continue."));
    process.exitCode = 20;
    return;
  }

  if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
}

const program = new Command();
program.name("husk").description("Agentic supply-chain malware scanner").version("0.1.0");

program
  .command("scan")
  .argument("[packageSpec]")
  .option("--file <package.json>", "Scan dependencies declared in a package.json")
  .option("--local <path>", "Scan a local package directory or tarball")
  .option("--json", "Output JSON")
  .option("--sandbox", "Force sandbox execution")
  .option("--static-only", "Disable sandbox execution")
  .option("--verbose", "Show all findings and stage timings")
  .action(async (packageSpec, options) => {
    if (options.file) {
      await scanManifestFile(options.file, options);
      return;
    }

    if (options.local) {
      await scanPackage(options.local, {
        local: options.local,
        json: options.json,
        sandbox: options.sandbox,
        staticOnly: options.staticOnly,
        verbose: options.verbose
      });
      return;
    }

    if (!packageSpec) {
      console.error("Provide a package spec, --file, or --local path.");
      process.exitCode = 1;
      return;
    }

    await scanPackage(packageSpec, options);
  });

program
  .command("intercept")
  .option("--enable", "Enable npm registry interception")
  .option("--disable", "Disable npm registry interception")
  .option("--status", "Show whether the intercept proxy is running")
  .option("--logs", "Print recent entries from .husk/intercept.log")
  .option("--tail <n>", "Number of log lines to print with --logs", "50")
  .option("--port <port>", "Local registry proxy port", String(DEFAULT_PORT))
  .action(async (options) => {
    const port = Number(options.port);

    if (options.logs) {
      const limit = Math.max(1, Number(options.tail) || 50);
      const lines = await readInterceptLog(limit);
      if (lines.length === 0) {
        console.log(PALETTE.muted(`No intercept events recorded yet (${getInterceptLogPath()}).`));
        return;
      }
      console.log(PALETTE.highlight.bold(`  Last ${lines.length} intercept event${lines.length === 1 ? "" : "s"}`));
      console.log(PALETTE.muted(`  ${getInterceptLogPath()}`));
      for (const line of lines) {
        try {
          const entry = JSON.parse(line) as Record<string, unknown>;
          const ts = String(entry.timestamp ?? "");
          const event = String(entry.event ?? "event");
          const pkg = entry.package ? ` ${PALETTE.command(String(entry.package))}` : "";

          // Each event type gets its own color and detail format so a
          // long log skim is parseable at a glance.
          const eventStyle: Record<string, (s: string) => string> = {
            "registry-takedown": PALETTE.danger,
            blocked: PALETTE.danger,
            warned: PALETTE.warn,
            allowed: PALETTE.safe,
            "tty-breadcrumb-error": PALETTE.muted,
            "tty-breadcrumb-write-error": PALETTE.muted,
            "tty-breadcrumb-throw": PALETTE.muted
          };
          const styleFn = eventStyle[event] ?? PALETTE.muted;

          let detail = "";
          if (event === "registry-takedown") {
            const versions = Array.isArray(entry.unpublishedVersions)
              ? (entry.unpublishedVersions as string[]).slice(0, 5).join(", ")
              : "";
            const placeholder = entry.securityPlaceholderVersion
              ? `, security=${entry.securityPlaceholderVersion as string}`
              : "";
            const fullUnpub = entry.fullPackageUnpublishedAt
              ? `, fully unpublished ${entry.fullPackageUnpublishedAt as string}`
              : "";
            detail = ` ${PALETTE.muted(`(${versions}${placeholder}${fullUnpub})`)}`;
          } else if (event === "blocked" || event === "warned" || event === "allowed") {
            const verdict = entry.verdict ? String(entry.verdict).toLowerCase() : "";
            const conf =
              typeof entry.confidence === "number" ? `${Math.round((entry.confidence as number) * 100)}%` : "";
            const ms = typeof entry.scanMs === "number" ? `${entry.scanMs}ms` : "";
            const bits = [verdict, conf && `conf ${conf}`, ms].filter(Boolean).join(" · ");
            detail = bits ? ` ${PALETTE.muted(`(${bits})`)}` : "";
            if (event === "blocked" && Array.isArray(entry.topReasons) && entry.topReasons.length > 0) {
              const top = (entry.topReasons as Array<{ severity: string; title: string }>)[0];
              detail += ` ${PALETTE.muted(`— ${top.severity}: ${top.title}`)}`;
            }
          }
          console.log(`  ${PALETTE.muted(ts)} ${styleFn(event)}${pkg}${detail}`);
        } catch {
          console.log(`  ${PALETTE.muted(line)}`);
        }
      }
      return;
    }

    if (options.status) {
      const status = await getInterceptStatus(port);
      const label = status.enabled ? PALETTE.safe("running") : PALETTE.muted("stopped");
      console.log(`  intercept ${label}`);
      console.log(`  ${PALETTE.muted("port")}    ${status.port}`);
      console.log(`  ${PALETTE.muted("pid")}     ${status.pid ?? "—"}`);
      console.log(`  ${PALETTE.muted("log")}     ${status.logPath}`);
      return;
    }

    if (options.enable) {
      const result = await enableIntercept(port);
      console.log("");
      const action = result.restarted ? "restarted" : "enabled";
      console.log(PALETTE.safe.bold(`  ✓ Husk interception ${action}`) + PALETTE.muted(` on http://localhost:${result.port} (pid ${result.pid})`));
      console.log(PALETTE.muted(`    .npmrc now points npm at the Husk proxy. Plain 'npm install' is gated.`));
      if (result.ttyPath) {
        console.log(PALETTE.muted(`    Live takedown banners will appear in this terminal (${result.ttyPath}).`));
      } else {
        console.log(PALETTE.warn(`    ⚠ No controlling TTY detected — live banners disabled.`));
        console.log(PALETTE.muted(`      Run 'husk intercept --enable' from an interactive shell to enable them,`));
        console.log(PALETTE.muted(`      or use 'husk intercept --logs' to review events after the fact.`));
      }
      console.log("");
      console.log(PALETTE.highlight.bold("    Recommended workflow:"));
      console.log(`      ${PALETTE.command.bold("npm install <pkg>@<ver>")} ${PALETTE.muted("(transitive deps + tarballs are scanned)")}`);
      console.log(`      ${PALETTE.command.bold("husk intercept --logs")}    ${PALETTE.muted("(view registry-takedown / block events)")}`);
      console.log(`      ${PALETTE.command.bold("husk intercept --disable")} ${PALETTE.muted("(restore npmrc, stop proxy)")}`);
      console.log("");
      console.log(PALETTE.muted(`    Note: pinned-version takedowns (e.g. unpublished versions) cause npm`));
      console.log(PALETTE.muted(`    to fail with ETARGET. Husk surfaces a takedown banner above the npm`));
      console.log(PALETTE.muted(`    error and logs the event to ${getInterceptLogPath()}.`));
      console.log(PALETTE.muted(`    For a full verdict card, also run: ${PALETTE.command("husk scan <pkg>@<ver>")}`));
      console.log("");
      return;
    }

    if (options.disable) {
      await disableIntercept();
      console.log(PALETTE.safe(`  ✓ Husk interception disabled.`) + PALETTE.muted(` (.npmrc restored)`));
      return;
    }

    console.log(PALETTE.muted("Use --enable, --disable, --status, or --logs."));
  });

program
  .command("decide")
  .argument("<manager>", "Package manager to guard: npm or pip")
  .argument("<packages...>", "Packages to evaluate before installation")
  .option("--json", "Output JSON")
  .option("--sandbox", "Force sandbox execution for npm packages")
  .option("--static-only", "Disable sandbox execution")
  .action(async (manager, packageSpecs, options) => {
    try {
      const plan = await decidePackages(assertInstallManager(manager), packageSpecs, options);
      process.exitCode = plan.overallAction === "BLOCK" ? 40 : plan.overallAction === "WARN" ? 20 : 0;
    } catch (error) {
      // RegistryError was already rendered as a verdict card by decidePackages.
      // For unpublished/security-placeholder errors, treat the run as a BLOCK.
      if (error instanceof RegistryError) {
        const isSecuritySignal =
          error.code === "unpublished-version" ||
          error.code === "unpublished-package" ||
          error.code === "security-placeholder";
        process.exitCode = isSecuritySignal ? 40 : 1;
      } else {
        console.error(error instanceof Error ? error.message : String(error));
        process.exitCode = 1;
      }
    }
  });

program
  .command("install")
  .argument("<manager>", "Package manager to run through Husk: npm or pip")
  .argument("<packages...>", "Packages to install after Husk evaluation")
  .option("--dry-run", "Analyze but do not execute the underlying install command")
  .option("--json", "Output the install decision as JSON and do not install")
  .option("--yes", "Automatically continue when Husk returns WARN")
  .option("--force", "Override Husk BLOCK decisions")
  .option("--sandbox", "Force sandbox execution for npm packages")
  .option("--static-only", "Disable sandbox execution")
  .action(async (manager, packageSpecs, options) => {
    try {
      await installPackages(assertInstallManager(manager), packageSpecs, options);
    } catch (error) {
      if (error instanceof RegistryError) {
        const isSecuritySignal =
          error.code === "unpublished-version" ||
          error.code === "unpublished-package" ||
          error.code === "security-placeholder";
        process.exitCode = isSecuritySignal ? 40 : 1;
        return;
      }
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

program
  .command("benchmark")
  .action(async () => {
    const tsxCli = resolve(PROJECT_ROOT, "node_modules/tsx/dist/cli.mjs");
    const runner = resolve(PROJECT_ROOT, "benchmark/runner.ts");

    if (!existsSync(tsxCli)) {
      console.error(chalk.red("  ✖ Benchmark dependency missing: tsx is not installed."));
      console.error(chalk.dim(`    Run 'npm install' inside ${PROJECT_ROOT} to restore the benchmark toolchain.`));
      process.exitCode = 1;
      return;
    }

    if (!existsSync(runner)) {
      console.error(chalk.red("  ✖ Benchmark runner not found at benchmark/runner.ts."));
      console.error(chalk.dim(`    Expected location: ${runner}`));
      process.exitCode = 1;
      return;
    }

    const exitCode = await new Promise<number>((resolveCode) => {
      const child = spawn(process.execPath, [tsxCli, runner], {
        stdio: "inherit",
        cwd: PROJECT_ROOT
      });
      child.on("error", () => resolveCode(1));
      child.on("exit", (code) => resolveCode(code ?? 1));
    });

    if (exitCode !== 0) {
      console.error("");
      console.error(chalk.red(`  ✖ Benchmark exited with code ${exitCode}.`));
      process.exitCode = exitCode;
    }
  });

program
  .command("dashboard")
  .action(async () => {
    printBanner();
    const module = await import("../dashboard/server.js");
    await module.startDashboardServer();
  });

const topLevelHelpRequested =
  process.argv.length === 3 && ["--help", "-h", "help"].includes(process.argv[2]);

// Wrapper-style invocation: `husk npm install <pkgs>` and `husk pip install <pkgs>`.
// Matches the natural "husk wraps the command, runs the gate first, then runs
// the real command if approved" mental model. We rewrite argv so the existing
// `install` subcommand handles it.
//   npm install | npm i | npm add  →  husk install npm <pkgs>
//   pip install                    →  husk install pip <pkgs>
// Bare `npm install` / `npm ci` (no packages) installs from a manifest, which
// is a different flow — we point the user at `husk scan --file` or `husk intercept`.
const NPM_INSTALL_SUBS = new Set(["install", "i", "add"]);
const PIP_INSTALL_SUBS = new Set(["install"]);
const wrapperManager =
  process.argv.length >= 4 &&
  ((process.argv[2] === "npm" && NPM_INSTALL_SUBS.has(process.argv[3])) ||
    (process.argv[2] === "pip" && PIP_INSTALL_SUBS.has(process.argv[3])))
    ? process.argv[2]
    : null;

if (process.argv.length <= 2 || topLevelHelpRequested) {
  printWelcome();
  process.exit(0);
}

if (wrapperManager) {
  const subcommand = process.argv[3];
  const tail = process.argv.slice(4);

  // Three categories of args after `npm install`:
  //   1. package specs (no leading dash)
  //   2. Husk install flags — re-routed to the underlying `husk install` command
  //   3. package-manager flags (e.g. -D, --save-dev) — NOT forwarded today
  const HUSK_INSTALL_FLAGS = new Set([
    "--dry-run",
    "--json",
    "--yes",
    "--force",
    "--sandbox",
    "--static-only"
  ]);
  const packageSpecs: string[] = [];
  const huskFlags: string[] = [];
  const dropped: string[] = [];
  for (const arg of tail) {
    if (!arg.startsWith("-")) packageSpecs.push(arg);
    else if (HUSK_INSTALL_FLAGS.has(arg)) huskFlags.push(arg);
    else dropped.push(arg);
  }

  if (packageSpecs.length === 0) {
    console.error("");
    console.error(PALETTE.warn(`  ⚠ '${wrapperManager} ${subcommand}' with no packages installs from a manifest file.`));
    console.error(PALETTE.muted("    Husk's wrapper form gates explicit package installs."));
    console.error(PALETTE.highlight.bold("    For manifest-based installs, use one of these:"));
    console.error(`      ${PALETTE.command.bold("husk scan --file package.json")} ${PALETTE.muted("(scan every dep listed in package.json)")}`);
    console.error(`      ${PALETTE.command.bold("husk intercept --enable")} ${PALETTE.muted("(then plain 'npm install' is auto-guarded)")}`);
    console.error("");
    process.exit(1);
  }

  if (dropped.length > 0) {
    console.error("");
    console.error(PALETTE.warn(`  ⚠ Husk's wrapper form does not forward package-manager flags: ${dropped.join(" ")}`));
    console.error(PALETTE.muted("    For full flag forwarding, run 'husk intercept --enable' and use plain 'npm install ...'."));
    console.error("");
  }

  // Rewrite argv so Commander sees `husk install [husk-flags] <manager> <pkgs...>`.
  process.argv = [
    process.argv[0],
    process.argv[1],
    "install",
    ...huskFlags,
    wrapperManager,
    ...packageSpecs
  ];
}

await program.parseAsync(process.argv);
