#!/usr/bin/env node
// Husk diagnostic — verifies the investigator agent (the autonomous
// re-investigation loop) actually fires on borderline verdicts and stays
// silent on clean ones. This is the ground-truth test for "is the agentic
// flow working?".
//
// What it does:
//   1. Scans a known-borderline package (or one you provide) and shows the
//      investigator's decisions: did it fire, which files did it pick to
//      read, what question did it frame, what did it recommend?
//   2. Optionally also scans a known-clean package to confirm the
//      investigator does NOT fire (efficiency / no-overhead property).
//
// Usage:
//   node scripts/check-investigator.mjs
//     → uses test-fixtures/evil-credential-exfil as the borderline case
//   node scripts/check-investigator.mjs --local <path-to-package>
//   node scripts/check-investigator.mjs <package-spec>
//   node scripts/check-investigator.mjs --no-clean-check    skip the clean-package side
//
// Exit codes:
//   0  investigator behaved correctly (fired on borderline, silent on clean)
//   1  investigator did not fire on the borderline case (AI broken or gating bug)
//   2  investigator fired on a clean popular package (false-trigger regression)

import { execSync } from "node:child_process";

const C = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  cyan: "\x1b[36m"
};

const args = process.argv.slice(2);
const skipClean = args.includes("--no-clean-check");
const localFlag = args.indexOf("--local");
let target;
let isLocal = false;
if (localFlag >= 0) {
  target = args[localFlag + 1];
  isLocal = true;
} else {
  const positional = args.find((a) => !a.startsWith("--"));
  target = positional ?? "test-fixtures/evil-credential-exfil";
  isLocal = !target.match(/^[@a-z0-9]/i) || target.startsWith("test-fixtures/") || target.includes("/");
  // Heuristic: treat as local if it looks like a path
  isLocal = target.includes("/") && !target.startsWith("@");
}

function runScan(spec, useLocal) {
  const cmd = useLocal
    ? `husk scan --local "${spec}" --static-only --json 2>/dev/null`
    : `husk scan ${spec} --static-only --json 2>/dev/null`;
  process.stderr.write(`${C.dim}running: ${cmd}${C.reset}\n`);
  return execSync(cmd, { encoding: "utf8", maxBuffer: 1024 * 1024 * 16 });
}

function summarizeScan(label, raw) {
  let v;
  try {
    v = JSON.parse(raw);
  } catch (err) {
    console.log(`${C.red}✗ ${label}: could not parse scan output as JSON${C.reset}`);
    console.log(`  ${err.message}`);
    return null;
  }
  return v;
}

console.log("");
console.log(`${C.bold}Layer A — borderline scan (investigator should fire)${C.reset}`);
console.log(`${C.dim}target: ${target}${C.reset}`);
const borderline = summarizeScan("borderline scan", runScan(target, isLocal));
if (!borderline) process.exit(2);

const inv = borderline.investigation ?? null;
const verdict = borderline.verdict;
const conf = Math.round((borderline.confidence ?? 0) * 100);

console.log("");
console.log(`  package:           ${C.cyan}${borderline.packageName}@${borderline.packageVersion}${C.reset}`);
console.log(`  verdict:           ${verdict} (confidence ${conf}%)`);
console.log(`  policy action:     ${borderline.policy?.action}`);
console.log("");

if (!inv) {
  console.log(`  ${C.red}✗ no investigation field in scan output${C.reset}`);
  console.log(`  This means Husk's investigator wiring is broken or you're running an old build.`);
  console.log(`  Try: npm run build  &&  re-run this script.`);
  process.exit(1);
}

console.log(`  investigator fired: ${inv.triggered === true ? `${C.green}YES${C.reset}` : `${C.red}NO${C.reset}`}`);
console.log(`  trigger reason:     ${inv.reason}`);

if (!inv.triggered) {
  if (inv.reason === "ai-disabled") {
    console.log("");
    console.log(`  ${C.red}✗ AI is disabled.${C.reset} Investigator can never fire without a working API key.`);
    console.log(`  Run: ${C.cyan}node scripts/check-ai.mjs${C.reset} to diagnose your AI setup.`);
    process.exit(1);
  }
  if (inv.reason === "clean-no-signals" || inv.reason === "verdict-confident" || inv.reason === "critical-signal-present") {
    console.log("");
    console.log(`  ${C.yellow}⚠ Verdict was not borderline${C.reset} — nothing for the investigator to do here.`);
    console.log(`  Try a different target (a borderline package). The default reproducer is:`);
    console.log(`    ${C.cyan}node scripts/check-investigator.mjs --local test-fixtures/evil-credential-exfil${C.reset}`);
    process.exit(1);
  }
  console.log(`  ${C.yellow}⚠ Investigator declined to fire on a borderline case${C.reset} — gating may be too tight.`);
  process.exit(1);
}

console.log(`  duration:           ${inv.durationMs}ms`);
console.log(`  files inspected:    ${JSON.stringify(inv.filesInspected ?? [])}`);
console.log(`  focus question:     ${inv.focusQuestion ?? "(none)"}`);
console.log(`  recommendation:     ${inv.recommendation}`);
console.log(`  agent confidence:   ${inv.agentConfidence}`);
console.log(`  rationale:`);
console.log(`    ${(inv.rationale ?? "").slice(0, 360)}`);
console.log("");

if (skipClean) {
  console.log(`${C.green}✓ Layer A passed.${C.reset} (Skipping Layer B per --no-clean-check.)`);
  process.exit(0);
}

console.log(`${C.bold}Layer B — clean scan (investigator should NOT fire)${C.reset}`);
console.log(`${C.dim}target: react@18.2.0${C.reset}`);
const clean = summarizeScan("clean scan", runScan("react@18.2.0", false));
if (!clean) process.exit(2);

const cleanInv = clean.investigation;
console.log(`  verdict:            ${clean.verdict} (confidence ${Math.round((clean.confidence ?? 0) * 100)}%)`);
console.log(`  investigator fired: ${cleanInv?.triggered === true ? `${C.red}YES (regression!)${C.reset}` : `${C.green}NO${C.reset}`}`);
console.log(`  reason:             ${cleanInv?.reason ?? "(no investigation field)"}`);
console.log("");

if (cleanInv?.triggered) {
  console.log(`${C.red}✗ Layer B FAILED — investigator fired on a clean popular package.${C.reset}`);
  console.log(`This is a false-trigger regression. Investigate the borderline gating in`);
  console.log(`src/agents/investigator-agent.ts → shouldInvestigate().`);
  process.exit(2);
}

console.log(`${C.green}${C.bold}✓ Both layers passed.${C.reset} Investigator is firing on borderline cases and staying silent on clean ones — agentic flow is working as designed.`);
