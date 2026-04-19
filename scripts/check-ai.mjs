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

const stages = ["triage", "dynamicNarration", "reporting"];
let failures = 0;
for (const stage of stages) {
  const s = wf[stage] ?? {};
  const err = s.error;
  if (err) {
    failures++;
    const code = err.code ?? err.type ?? err.status ?? "unknown";
    console.log(`  ${C.red}✗ ${stage.padEnd(18)}${C.reset}  ${C.dim}mode=${s.mode}${C.reset}  ${C.red}FAILED${C.reset} ${code}: ${err.message?.slice(0, 100)}`);
  } else if (s.mode === "deterministic") {
    console.log(`  ${C.yellow}⚠ ${stage.padEnd(18)}${C.reset}  ${C.dim}mode=${s.mode}${C.reset}  ${C.yellow}fallback (no AI call attempted)${C.reset}`);
  } else {
    console.log(`  ${C.green}✓ ${stage.padEnd(18)}${C.reset}  ${C.dim}mode=${s.mode}  model=${s.model ?? "(default)"}${C.reset}`);
  }
}
console.log("");

if (failures > 0) {
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

console.log(`${C.green}${C.bold}All AI stages are healthy.${C.reset}`);
