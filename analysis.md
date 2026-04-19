I now have a deep, precise understanding of the project. Let me give you the analysis.

---

# Project Analysis: Husk

This is a TypeScript-built, Node.js (ESM) **agentic supply-chain malware scanner** for npm and PyPI dependencies. The project is named `husk` (`package.json` line 2) and exposes a CLI binary `husk` via `dist/cli/index.js`. It is a hackathon project framed as **"an AI-native dependency gate for developers and coding agents"** — not just a scanner, but a *decision layer* that intercepts, evaluates, and either allows, warns, or blocks package installs before they hit your machine.

The `changelog.md` is not a normal changelog — it is a **living "project memory"** doc (lines 1–14) that future agent sessions are supposed to read first instead of re-walking the whole codebase. My analysis below confirms that document's claims against the actual code.

---

## 1. What problem does Husk actually solve?

A normal coding assistant only sees code *after* you ask. A regular AV/scanner only checks files passively. Husk inserts itself into the **install path**:

- You either run `husk decide`/`husk install`/`husk scan`, or you turn on `husk intercept` which proxies the npm registry through a local Express server on port `4873` (`src/cli/intercept.ts:12`, `:114-191`) by writing `registry=http://localhost:4873` into your project `.npmrc` (`:32-46`).
- Every tarball npm tries to download gets pulled to `/tmp`, fully analyzed by Husk, and then either forwarded with `x-husk-policy-action`/`x-husk-verdict` headers or rejected with HTTP `403` (`src/cli/intercept.ts:118-157`).
- The same orchestrator powers CLI flows and the live dashboard, so the verdict is consistent everywhere (`src/agents/orchestrator.ts:30-128`).

The output is intentionally **dual-purpose**: human-readable verdict text + machine-readable JSON for automation/agents. Exit codes are policy-aware: `0=ALLOW`, `20=WARN`, `40=BLOCK`, `1=error` (`src/cli/index.ts:202-216`, `:284-292`).

---

## 2. Top-level layout

```
src/
├── cli/                    CLI entry, guarded install, npm intercept proxy
├── agents/                 Orchestrator + 5 "agents" (triage, deobfuscator, dynamic, verdict, reporter) + AI workflow
├── core/                   Types, registry client, package fetcher, policy engine
├── subsystems/             ioc-matcher, deobfuscator, behavior-diff, sandbox, typosquat
└── dashboard/              Express + static SPA (HTML/CSS/JS), SSE live feed
benchmark/                  Loader / runner / report for DataDog + Backstabbers datasets
docker/                     Dockerfile.sandbox + entrypoint.sh + seccomp-husk.json
test/                       vitest unit + integration + fixtures (5 malicious, 5 benign)
scripts/setup.sh            Clones datasets, builds sandbox image, prints provider status
husk.policy.example.json    Policy file template
.env.example                AI provider config template
changelog.md                Project memory doc (the spec)
```

---

## 3. End-to-end flow (the spine of the system)

`HuskOrchestrator.analyze()` in `src/agents/orchestrator.ts:30-128` is the spine. Reading it line-by-line:

1. **Emit `scan:started`** event (line 32-36) — used by the SSE dashboard.
2. **Prepare the package** via `PackageFetcher.preparePackage` (`src/core/package-fetcher.ts:35-102`):
   - If the spec looks local (`./`, `/`, `.tgz`, or exists on disk) → snapshots the directory into a tarball or extracts an existing tarball.
   - Otherwise resolves from the registry: `https://registry.npmjs.org/<name>` or `https://pypi.org/pypi/<name>/json` (`src/core/registry.ts:122-178`), captures the previous version via semver sort (`:195-204`), picks only `preinstall`/`install`/`postinstall`/`prepare` scripts (`:186-193`).
3. **Typosquat check** for npm only (`orchestrator.ts:40`) — `TyposquatDetector` normalizes `0→o, 1→l, rn→m, _-/@→empty`, runs Levenshtein (via the `leven` package) plus a keyboard-adjacency score and a scope-squat check (`src/subsystems/typosquat/index.ts:19-77`).
4. **Triage** (`TriageAgent.decide`, `src/agents/triage-agent.ts`) uses an LLM with a Zod-validated schema to choose which of `{sandbox, deobfuscator, diff}` to run. If AI fails or no key, falls back to a **deterministic** rule: install scripts present, recent publish (<7 days), native/wasm hints, typosquat signal, or previous-version availability (lines 59-78).
5. **Decide if sandbox is feasible** (lines 51-57): only npm, only if Docker socket + `husk-sandbox` image are ready (`src/subsystems/sandbox/docker-manager.ts:18-26`). `--sandbox` forces it and throws if not ready.
6. **Run the four static/dynamic subsystems in parallel** via `Promise.all` (lines 59-77):
   - `IOCMatcher.match` — always
   - `DeobfuscatorAgent.analyzePackage` — if triage said so
   - `BehaviorDiffEngine.diff` — if triage said so AND ecosystem is npm
   - `SandboxManager.analyze` — if Docker is ready and triage/`--sandbox` said so
7. **Verdict** via `VerdictAgent.decide` (`src/agents/verdict-agent.ts`) — see scoring below.
8. **Narrative** via `DynamicAgent.narrate` (LLM, with deterministic 4-bullet template fallback at lines 33-52).
9. **Policy** via `PolicyEngine.evaluate` — converts verdict to `ALLOW`/`WARN`/`BLOCK`.
10. **Advisory** via `ReporterAgent.generate` — Markdown writeup with a mandatory **"Safe Next Move"** section.
11. **Workflow summary** records which provider/model was actually used per stage (`buildWorkflowSummary`, lines 130-145).
12. Cleans up tmp dirs in `finally`.

---

## 4. The five "agents" and the AI workflow

Despite the name, only **three of the five** agents actually call an LLM:

| Agent | LLM? | What it does | File |
|---|---|---|---|
| `TriageAgent` | yes | Picks which scanners to run (structured JSON) | `src/agents/triage-agent.ts` |
| `DeobfuscatorAgent` | no | Wraps the AST pipeline, scans up to 25 files <300KB each, picks max suspicion score | `src/agents/deobfuscator-agent.ts` |
| `DynamicAgent` | yes | Narrates sandbox findings as 4 markdown bullets | `src/agents/dynamic-agent.ts` |
| `VerdictAgent` | no | Pure deterministic scoring engine | `src/agents/verdict-agent.ts` |
| `ReporterAgent` | yes (skipped on CLEAN) | Writes the human-facing markdown advisory | `src/agents/reporter-agent.ts:9-16` |

The AI plumbing is in `src/agents/ai-workflow.ts` and is the most carefully engineered part of the codebase:

- **Provider auto-selection** (`resolveAIWorkflowProviderConfig`, lines 246-301): respects `AI_PROVIDER`; otherwise prefers OpenAI if `OPENAI_API_KEY` set, else OpenRouter if `OPENROUTER_API_KEY` set, else nothing → fully deterministic.
- **Two transports**: OpenAI uses the **Responses API** with `responses.parse` + `zodTextFormat` for structured output (lines 530-548). OpenRouter uses **chat completions** with `chat.completions.parse` + `zodResponseFormat` (lines 508-527). The OpenRouter call asks for `plugins: [{id: "response-healing"}]` and `provider: { require_parameters: true }` to harden against models that drop schema fields.
- **Per-stage model + fallback chain** (`StageConfig`, lines 12-17, defaults at 61-103): each stage (`triage`/`dynamicNarration`/`reporting`) has its own model, max tokens, reasoning effort, and a list of fallback model names that get tried in order if a model returns empty output or errors.
- **Retries with backoff + Retry-After** (`runWithRetry`, lines 428-462): respects HTTP `Retry-After` headers, classifies errors as retriable for 503/408/429 (excluding `insufficient_quota`) plus connection/timeout (lines 394-401), exponential backoff `DEFAULT_RETRY_BASE_MS * 2^(attempt-1)`.
- **Stage error tracking** (`describeStage`, lines 356-365): if AI fails, the stage is reported as `mode: "deterministic"` with the captured error attached, so the CLI can yellow-print fallback warnings (`src/cli/index.ts:63-81`).

Note: the source contains references to `gpt-5.4`/`gpt-5.4-mini` (`ai-workflow.ts:63, 69, 75`) and `gpt-5-mini`/`gpt-5-nano` (`.env.example:5-7`), and the test asserts `gpt-5.4-mini` (`test/ai-workflow.test.ts:14`). These are forward-looking model identifiers chosen by the author for a 2026 hackathon; whether they resolve depends on what the configured provider actually serves — that's exactly why the fallback chain to `openai/gpt-4.1-mini` and `openrouter/auto` exists (`ai-workflow.ts:82`).

---

## 5. Detection subsystems

### 5.1 IOC Matcher (`src/subsystems/ioc-matcher/`)

A rule engine over five rule types defined in `core/types.ts:170-201`:
- `filename`, `content_regex`, `script_pattern`, `package_version`, `domain`.

Two rule packs:

- **Shai-Hulud** (`rules/shai-hulud.ts`) — targets the real-world npm worm: filenames `bun_environment.js`, `setup_bun.js`, `shai-hulud-workflow.yml`; the compromised `@ctrl/tinycolor@4.1.2`; Discord webhook / `transfer.sh` / `shai-hulud` infrastructure markers; and exfil regex for `process.env.GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY|AWS_SECRET`.
- **Generic** (`rules/generic.ts`) — eval+child_process, base64+eval, literal IPs, `dns.resolve`, `.npmrc/.pypirc/authorized_keys/id_rsa` references, hex-obfuscated `require("child_process")`, `curl ... | bash` in lifecycle scripts.

Plus a curated `KNOWN_C2_DOMAINS` list (`c2-domains.ts`).

The PyPI false-positive fix mentioned in the changelog is real and at `index.ts:132-138`: the literal-IP regex only fires on executable-like extensions (`.js/.cjs/.mjs/.ts/.tsx/.sh/.bash/.zsh/.ps1`) or `package.json`. The `ioc-matcher.test.ts` exercises both directions (benign Python with `192.168.1.1` is ignored; JS with the same IP is flagged).

### 5.2 Deobfuscator (`src/subsystems/deobfuscator/`)

A real **iterative AST-rewriting pipeline** built on `@babel/parser` + `@babel/traverse`. Up to 10 passes, each running 5 visitors in order until the generated source stops changing (`pipeline.ts:81-117`):

1. `string-decode` — unescapes `\x..`/`\u00..`, evaluates `String.fromCharCode(...)`, decodes `atob(...)` and `Buffer.from(b64,"base64").toString()`.
2. `string-array` — handles obfuscator-style string-table indirection.
3. `eval-unwrap` — replaces `eval("...")` and `new Function(...)("")` calls with the parsed AST (`visitors/eval-unwrap.ts:43-76`).
4. `constant-fold` — folds binary/string concat constants.
5. `wrapper-inline` — inlines IIFE/wrapper functions.

After each pass, `suspicion-scorer.ts` re-walks the AST counting "sinks" (`require:child_process`, `exec`, `spawn`, `process.env.X`, etc.), URLs, and suspicious string literals. Final score = `min(100, sinks*10 + urls*20 + strings*2)`. The integration test (`test/integration/deobfuscator.test.ts`) confirms `eval(Buffer.from(b64,"base64").toString())` becomes literal `console.log("evil")`.

### 5.3 Behavior Diff (`src/subsystems/behavior-diff/`)

For npm only. Downloads the previous version from the registry and:

- Computes an **AST capability fingerprint** (`ast-fingerprint.ts`): tracks `require`/`import` modules, member calls on aliased modules (`fs.writeFile` etc.), `process.env.X` access, embedded URLs, and dependencies — all hashed into a SHA-256 over the sorted set.
- Diffs candidate-vs-previous capability sets and maps each new/removed capability into `{network, filesystem, process, dependency, env, script}` buckets (`capability-diff.ts:3-25`).
- Diffs all files via SHA-256 hashes (`index.ts:26-55`).
- Diffs install scripts as a unified `+/-` text block.
- Suspicion score = `newCaps*8 + changedFiles*2 + (installScriptChanged?10:0)`, capped at 100.

If no previous version exists it returns a stub with `previousVersion: "none"` (lines 62-74).

### 5.4 Sandbox (`src/subsystems/sandbox/`)

Real Docker dynamic analysis (`docker-manager.ts`):
- Builds container from `husk-sandbox` image (Debian-slim Node 20 + `strace` + `curl`, runs as unprivileged `sandbox` user — `docker/Dockerfile.sandbox`).
- Hard limits: `Memory: 512MB`, `NanoCpus: 1B (=1 CPU)`, `CapDrop: ["ALL"]`, custom seccomp profile, network defaults to `bridge` only when `allowNetwork: true` else `none` (lines 53-68).
- 60s default timeout that kills the container and rejects (lines 100-111).
- Mounts the package tarball, runs `entrypoint.sh` which executes `strace -f -e trace=network,process,file,write,read -s 4096 -o /sandbox/trace.log npm install --ignore-scripts=false --no-save file:///sandbox/pkg.tgz` (the `false` is intentional — they *want* lifecycle scripts to fire so they can observe them).

Then `StraceParser` (`strace-parser.ts`) parses the raw trace into typed events:
- `open/openat` with `O_WRONLY|O_RDWR|O_CREAT` → `file_write`; matching paths like `.npmrc/.pypirc/.ssh/.aws/.github/workflows` → `file_read`; `/proc/self/environ` → `env_access`.
- `write(fd,...)` content scanned for `AWS_ACCESS_KEY_ID/GITHUB_TOKEN/NPM_TOKEN/...` (lines 9-17).
- `connect/sendto` with `sin_port=htons(N)` and a quoted address → `network`.
- `execve` → `process_spawn` with parsed args.

`BehaviorModel` (`behavior-model.ts`) classifies the events into `SuspicionFinding`s with rule IDs like `outbound-network`, `known-c2`, `credential-write-ssh/aws/npmrc`, `workflow-write`, `curl-bash`, `chmod-exec`, `secret-harvest`.

### 5.5 Typosquat (`src/subsystems/typosquat/`)

Already covered above. `popular-packages.ts` is a hardcoded ~100-package allow-list of well-known npm names used as both the typosquat reference and the benign benchmark sample.

---

## 6. Verdict scoring (deterministic)

`VerdictAgent.decide` (`src/agents/verdict-agent.ts:34-183`) is purely deterministic:

| Signal | Score |
|---|---|
| Per IOC | CRITICAL=40, HIGH=25, MEDIUM=15, LOW=5 |
| Sandbox network attempts (any) | +25 |
| Credential-write or secret-harvest finding | +35 |
| Workflow-write finding | +40 |
| Deobfuscation suspicion >50 | +20 |
| Deobfuscation revealed any URL | +35 |
| Behavior-diff added new network capability | +15 |
| Behavior-diff install script changed | +10 |
| Typosquat distance ≤1 | +20, else +10 |

Capped at 100. Thresholds: `≥60 → MALICIOUS`, `≥30 → SUSPICIOUS`, else `CLEAN`. Confidence = bounded `score/100` between 0.30 and 0.99.

`buildRecommendations` (lines 185-225) emits up to 5 "safe next move" actions: use the legit typosquat target, pin the previous version, rotate npm/GH/cloud/CI credentials, audit `.github/workflows`, use `--ignore-scripts` for further triage.

---

## 7. Policy engine (`src/core/policy.ts`)

Validated via Zod (`policySchema`, lines 10-19). Defaults: block MALICIOUS, warn SUSPICIOUS, block on critical IOCs / secret exposure / workflow tampering / typosquat distance ≤1, require review for SUSPICIOUS.

Loading order (lines 43-59): `HUSK_POLICY_PATH` → `./husk.policy.json` → `./.husk/policy.json` → built-in default. The example file `husk.policy.example.json` shows the schema in JSON.

`evaluate()` accumulates `blockReasons`/`warnReasons` from the verdict and returns first-match: any block reason → `BLOCK`, any warn reason → `WARN`, else `ALLOW`. Helpers `hasSecretExposure` (lines 61-67) and `hasWorkflowTampering` (lines 69-74) cross-check IOC descriptions, verdict reasons, and deobfuscation `env:` sinks.

---

## 8. CLI surface (`src/cli/index.ts`)

Built with Commander v12. Six commands:

- **`husk scan [pkg]`** with `--file/--local/--json/--sandbox/--static-only` — runs orchestrator, prints colored verdict + first 6 reasons + first 3 recommendations.
- **`husk decide <npm|pip> <pkgs...>`** — pre-install gate, exits `0/20/40` (`:287`).
- **`husk install <npm|pip> <pkgs...>`** with `--dry-run/--json/--yes/--force/--sandbox/--static-only` — calls `planGuardedInstall` then `executeGuardedInstall` which spawns the actual `npm install ...` or `python3 -m pip install ...` only after the policy check (`guarded-install.ts:113-137`). pip path is hard-coded to `staticOnly:true` and `disableSandbox:true` (`guarded-install.ts:67-73`).
- **`husk intercept --enable|--disable [--port]`** — spawns the proxy as a detached `tsx src/cli/intercept.ts --serve --port N` child, writes its PID to `.husk/intercept.pid`, edits `.npmrc`.
- **`husk benchmark`** — re-spawns Node on `benchmark/runner.ts` via tsx so it can use TS in the runtime.
- **`husk dashboard`** — dynamic-imports `src/dashboard/server.js` and starts it.

The CLI prints AI-fallback warnings in yellow (`printWorkflowWarnings`, lines 63-81) showing the provider, stage, and structured error — this is what makes the "AI is optional" promise honest.

---

## 9. Dashboard (`src/dashboard/`)

Express SPA (not Next.js, despite the polish):
- `GET /api/results` returns history + stats.
- `GET /api/stream` is the SSE endpoint backed by a Node `EventEmitter`; pushes `scan:queued/started/triage/completed/error/result` and `stats` events (`server.ts:43-60`).
- `POST /api/scan` queues an orchestrator run and broadcasts events.
- History capped at 50 entries (`:94`).

The `public/app.js` frontend listens to SSE, renders a live feed and a recent-verdicts list, draws a 3-bar canvas chart of `CLEAN/SUSPICIOUS/MALICIOUS` counts, and pops a modal automatically when a `MALICIOUS` verdict arrives (`app.js:128-141`). The "False Positive Rate" stat is a simplification (`server.ts:24`) — it's `suspicious / total` of dashboard history, not a true labeled FP rate; the changelog (§14.5) explicitly admits this.

---

## 10. Benchmark harness (`benchmark/`)

`scripts/setup.sh` clones two real-world malicious-package corpora into `datasets/`:
- **DataDog `malicious-software-packages-dataset`**
- **Backstabbers' `Backstabbers-Knife-Collection`**

Both are encrypted ZIPs with the well-known password `infected` (`loader.ts:140`).

`runner.ts` takes the first 50 npm malicious entries + first 50 popular benign packages, runs each through the orchestrator with `staticOnly: true` (no Docker → reproducible), and feeds results into `report.ts` which computes precision/recall/F1/FP-rate/median-scan-time and a per-category detection rate, then writes `benchmark-report.md` and `benchmark-report.json` into a fresh tmp dir.

A verdict counts as "detected" if it's `MALICIOUS` or `SUSPICIOUS` (`runner.ts:10-12`).

---

## 11. Tests (vitest, `test/`)

- **Unit**: `policy.test.ts` (block-on-critical-IOCs, allow-clean), `guarded-install.test.ts` (npm → `npm install ...`, pip → `python3 -m pip install ...`), `ai-workflow.test.ts` (provider precedence + per-stage model resolution + OpenRouter headers), `ioc-matcher.test.ts` (the PyPI literal-IP false-positive fix).
- **Integration**: `e2e.test.ts` (malicious fixture → BLOCK; benign fixture → ALLOW), `deobfuscator.test.ts` (base64+eval gets unwrapped to literal source), `sandbox.test.ts` (skips when Docker isn't available).
- **Fixtures**: 5 "malicious" packages embodying the IOC families: `lodas` (typosquat + preinstall + Discord webhook + workflow write), `payload.js` (base64-eval child_process curl|bash), `setup_bun.js` under `@crtl/tinycolor@4.1.2` (Shai-Hulud lookalike), plus stage/run samples; and 5 benign npm packages.
- `test/setup.ts` clears AI env vars so tests are deterministic regardless of your local `.env`.

---

## 12. Honest limitations (from the code, not just the doc)

- **PyPI is a second-class citizen.** `pip install` always runs static-only, no sandbox, no behavior-diff (`guarded-install.ts:67-73`); typosquat skipped (`orchestrator.ts:40`); the registry client doesn't even try to extract install scripts for PyPI (`registry.ts:154-178`).
- **Sandbox needs Docker Desktop + a pre-built `husk-sandbox` image.** Without them, `--sandbox` throws (`orchestrator.ts:55-57`); without the flag it silently degrades.
- **Intercept is npm-only.** No PyPI proxy.
- **Dashboard "False Positive Rate" is heuristic**, not benchmark-truth (admitted at `changelog.md:733-735`).
- **Custom seccomp profile is referenced** at `docker/seccomp-husk.json` and required by the Docker run config (`docker-manager.ts:66`), so the sandbox build does depend on it being present.

---

## 13. Short summary (what to pitch at the hackathon)

> Husk is a TypeScript CLI + dashboard + npm-registry proxy that turns dependency installs into an explainable, policy-driven `ALLOW`/`WARN`/`BLOCK` decision. It combines five real detection layers — IOC rules (incl. Shai-Hulud worm signatures), iterative AST deobfuscation, AST-based behavior diffing against the previous version, a Docker+strace dynamic sandbox, and typosquat detection — into a deterministic verdict, then optionally adds LLM-driven triage/narration/advisory writeups via OpenAI Responses or OpenRouter chat completions, with full deterministic fallback if the AI fails. It includes a benchmark harness over the public DataDog and Backstabbers malicious-package datasets and ships hackathon-ready: live SSE dashboard, npm intercept demo, malicious/benign fixtures, and a policy file format.

The `changelog.md` ([Husk Project Memory and Changelog](#)) is your single best presentation script — sections 1–4 are the elevator pitch, sections 5–9 are the architecture deep-dive, and section 14 is your honest "what's next" slide.