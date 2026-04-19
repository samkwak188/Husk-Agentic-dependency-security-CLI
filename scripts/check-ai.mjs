#!/usr/bin/env node
// Husk diagnostic — verifies the AI workflow is actually configured and
// reachable. Reads a `husk scan ... --json` payload from stdin (or scans
// `lodash@4.17.21` if no stdin is given) and prints which AI stages are
// working vs failing, with the exact upstream error message for each
// failure path so you can debug a misconfigured .env in one shot.
//
// Usage:
//   node scripts/check-ai.mjs                   # auto-scans lodash@4.17.21
//   node scripts/check-ai.mjs <package>         # scans the package you give it
//   husk scan foo --json | node scripts/check-ai.mjs    # consumes stdin

import { execSync } from "node:child_process";

const C = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  dim: "\x1b[2m",
  bold: "\x1b[1m"
};

async function readStdin() {
  if (process.stdin.isTTY) return null;
  return await new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
  });
}

function runScan(pkg) {
  process.stderr.write(`${C.dim}running: husk scan ${pkg} --static-only --json ...${C.reset}\n`);
  return execSync(`husk scan ${pkg} --static-only --json 2>/dev/null`, {
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 16
  });
}

const arg = process.argv[2] && !process.argv[2].startsWith("-") ? process.argv[2] : "lodash@4.17.21";
const stdinPayload = await readStdin();
const raw = stdinPayload && stdinPayload.trim().length > 0 ? stdinPayload : runScan(arg);

let payload;
try {
  payload = JSON.parse(raw);
} catch (err) {
  console.error(`${C.red}Could not parse husk scan output as JSON:${C.reset} ${err.message}`);
  console.error(`First 200 chars of payload: ${raw.slice(0, 200)}`);
  process.exit(2);
}

const wf = payload.workflow ?? {};
console.log("");
console.log(`${C.bold}AI workflow check${C.reset}  ${C.dim}(package: ${payload.packageName}@${payload.packageVersion})${C.reset}`);
console.log(`  provider:    ${wf.provider ?? "(none)"}`);
console.log(`  apiEnabled:  ${wf.apiEnabled === true ? `${C.green}true${C.reset}` : `${C.red}false${C.reset}`}`);
console.log("");

// Per-stage interpretation:
//   - `triage` always runs on every scan, so it's the canonical health check.
//   - `dynamicNarration` only runs when the sandbox produced output. On a
//     static-only scan (or any scan where the sandbox didn't fire) it
//     legitimately falls back to deterministic — that's expected, not a bug.
//   - `reporting` only runs when there's something noteworthy to narrate;
//     on a clean popular package it's intentionally skipped.
//
// We weight `triage` as the source of truth. The other two showing
// `deterministic` mode is informational, not a failure.
const stages = [
  { name: "triage", canonical: true, expectedSkipReason: null },
  { name: "dynamicNarration", canonical: false, expectedSkipReason: "no sandbox result for this scan" },
  { name: "reporting", canonical: false, expectedSkipReason: "nothing to narrate on a clean package" }
];

let triageWorking = false;
let triageFailed = false;
let failures = 0;

for (const { name, canonical, expectedSkipReason } of stages) {
  const s = wf[name] ?? {};
  const err = s.error;
  if (err) {
    failures++;
    if (canonical) triageFailed = true;
    const code = err.code ?? err.type ?? err.status ?? "unknown";
    console.log(`  ${C.red}✗ ${name.padEnd(18)}${C.reset}  ${C.dim}mode=${s.mode}${C.reset}  ${C.red}FAILED${C.reset} ${code}: ${err.message?.slice(0, 100)}`);
  } else if (s.mode === "deterministic") {
    if (canonical) {
      // triage going deterministic without an error means AI was never
      // even attempted — usually because the API key is missing.
      console.log(`  ${C.red}✗ ${name.padEnd(18)}${C.reset}  ${C.dim}mode=${s.mode}${C.reset}  ${C.red}AI not attempted (no API key loaded)${C.reset}`);
    } else {
      console.log(`  ${C.dim}- ${name.padEnd(18)}  mode=${s.mode}  ${C.reset}${C.dim}(${expectedSkipReason})${C.reset}`);
    }
  } else {
    if (canonical) triageWorking = true;
    console.log(`  ${C.green}✓ ${name.padEnd(18)}${C.reset}  ${C.dim}mode=${s.mode}  model=${s.model ?? "(default)"}${C.reset}`);
  }
}
console.log("");

if (triageWorking) {
  console.log(`${C.green}${C.bold}✓ AI is healthy.${C.reset}  ${C.dim}(triage stage exercised the configured model)${C.reset}`);
  console.log(`${C.dim}The two skipped stages above are normal — they only run when there's${C.reset}`);
  console.log(`${C.dim}a sandbox result to narrate or a malicious finding to report.${C.reset}`);
  console.log("");
  console.log(`${C.dim}To exercise narration + reporting too, scan a malicious fixture:${C.reset}`);
  console.log(`  ${C.cyan}node scripts/check-ai.mjs test-fixtures/evil-postinstall${C.reset}`);
  process.exit(0);
}

if (triageFailed || failures > 0) {
  console.log(`${C.red}${C.bold}${failures} of ${stages.length} stages are failing.${C.reset}`);
  console.log(`Common fixes:`);
  console.log(`  • 402 "Insufficient credits" → top up at https://openrouter.ai/settings/credits`);
  console.log(`                                  OR change OPENROUTER_MODEL to a :free model`);
  console.log(`                                  (e.g. meta-llama/llama-3.3-70b-instruct:free)`);
  console.log(`  • 404 "No endpoints found"   → your OPENROUTER_MODEL doesn't exist on OpenRouter.`);
  console.log(`                                  Verify the model name at https://openrouter.ai/models`);
  console.log(`  • 401 "Unauthorized"         → invalid or revoked API key. Rotate at`);
  console.log(`                                  https://openrouter.ai/keys`);
  process.exit(1);
}

if (wf.apiEnabled === false) {
  console.log(`${C.yellow}AI is disabled (no API key loaded).${C.reset}`);
  console.log(`Husk fell back to deterministic mode for every stage.`);
  console.log(`To enable: set OPENROUTER_API_KEY (or OPENAI_API_KEY) in your .env file.`);
  process.exit(1);
}

console.log(`${C.yellow}AI status indeterminate — triage didn't fire and no error was reported.${C.reset}`);
process.exit(1);
