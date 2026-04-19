# Husk Project Memory and Changelog

Last updated: 2026-04-18

This file is a living project memory document for the Husk codebase. It is intentionally broader than a normal changelog. Its purpose is to capture:

- What Husk is
- What problem it solves
- What is actually implemented today
- How the system works end to end
- How users and agents should use it
- What is strong, what is partial, and what is still missing

Future conversations about this repo should use this file as the first source of truth before re-reading the entire codebase.

## 1. Purpose

Husk is an agentic supply-chain security tool for dependency installs.

Its goal is to stop malicious or risky packages before they are installed, explain why they are risky, and tell the user what to do next.

Husk is not only a scanner. The current product direction is:

- analyze dependencies before install
- decide whether to allow, warn, or block
- provide actionable remediation and safe alternatives
- support both direct human CLI use and machine-readable policy decisions for automation or coding agents

The strongest product framing is:

Husk is an AI-native dependency gate for developers and coding agents.

This is more precise than calling it only a malware scanner.

## 2. Current Product Scope

Today Husk supports:

- explicit package scans
- guarded dependency decisions
- guarded installs for `npm` and `pip`
- npm registry interception and blocking
- optional Docker sandboxing for npm packages
- OpenRouter or OpenAI-backed triage/reporting
- deterministic fallback when no AI provider is available
- live dashboard with SSE updates
- benchmark harness against malicious-package datasets

Today Husk is strongest for npm. PyPI support exists, but is narrower:

- PyPI resolution and guarded install decision are implemented
- PyPI transparent interception is not implemented
- sandbox execution is npm-oriented and Docker/Linux based
- behavior diff and typosquat logic are npm-focused

## 3. What Makes Husk Distinct

The repo is designed to solve a problem that a normal coding assistant does not solve by itself:

- Coding assistants can inspect code after you ask them.
- Husk sits in the dependency install path and makes an explicit policy decision before install.
- Husk produces both human-friendly and machine-readable outcomes.
- Husk gives "safe next move" guidance instead of only verdicts.

Key differentiators currently implemented:

- allow/warn/block policy engine
- guard mode style commands: `decide` and `install`
- AI-assisted triage and reporting with deterministic fallback
- actionable remediation in verdicts and advisories
- npm interception path that uses the same policy logic as CLI decisions

## 4. Implemented Commands

The CLI entry point is `src/cli/index.ts`.

Current commands:

### 4.1 `husk scan`

Purpose:
- scan a package directly and return a verdict

Examples:

```bash
husk scan lodash@4.17.21
husk scan --local test/fixtures/malicious/sample1
husk scan --file package.json
```

Important flags:

- `--file <package.json>`: scan dependencies from a manifest
- `--local <path>`: scan a local directory or tarball
- `--json`: emit structured JSON
- `--sandbox`: force Docker sandboxing when available
- `--static-only`: disable sandbox execution

### 4.2 `husk decide`

Purpose:
- evaluate a dependency install request before installation
- return a machine-readable and human-readable plan

Examples:

```bash
husk decide npm lodash@4.17.21
husk decide npm ./test/fixtures/malicious/sample1 --json
husk decide pip requests==2.32.3 --json
```

Supported managers:

- `npm`
- `pip`

Exit codes:

- `0`: allow
- `20`: warn / review required
- `40`: blocked by policy
- `1`: CLI or runtime error

### 4.3 `husk install`

Purpose:
- evaluate first, then execute the underlying package-manager install only if policy allows or user overrides

Examples:

```bash
husk install npm lodash@4.17.21
husk install npm ./test/fixtures/benign/sample1 --dry-run
husk install pip requests==2.32.3 --dry-run
```

Important flags:

- `--dry-run`: analyze but do not execute install
- `--json`: emit the decision plan without installing
- `--yes`: automatically continue on `WARN`
- `--force`: override `BLOCK`
- `--sandbox`: force sandbox execution for npm
- `--static-only`: disable sandbox execution

Behavior:

- `BLOCK` + no `--force` => install does not run
- `WARN` + no `--yes` => interactive confirmation when possible
- `ALLOW` => underlying package manager runs

### 4.4 `husk intercept`

Purpose:
- turn npm installation into a policy-enforced flow through a local registry proxy

Examples:

```bash
husk intercept --enable
husk intercept --disable
```

Behavior:

- starts a local proxy on port `4873` by default
- writes `registry=http://localhost:<port>` into project `.npmrc`
- rewrites npm metadata tarball URLs through Husk
- scans each tarball before forwarding
- blocks requests with HTTP `403` when policy says `BLOCK`

### 4.5 `husk dashboard`

Purpose:
- start the live dashboard server

Example:

```bash
PORT=3101 husk dashboard
```

### 4.6 `husk benchmark`

Purpose:
- run the static-only benchmark harness over malicious and benign samples

Example:

```bash
husk benchmark
```

## 5. Core Scan Workflow

The main orchestrator is `src/agents/orchestrator.ts`.

For a normal scan, the flow is:

1. Resolve or prepare the package
2. Read metadata and package contents
3. Run triage
4. Decide which subsystems to invoke
5. Run selected subsystems in parallel
6. Score the findings into a verdict
7. Apply policy to produce `ALLOW`, `WARN`, or `BLOCK`
8. Produce narrative and advisory output
9. Return a unified `HuskVerdict`

### 5.1 Package Preparation

Handled by `src/core/package-fetcher.ts`.

Supported inputs:

- npm registry packages
- PyPI registry packages
- local directories
- local tarballs

For local directories:

- Husk creates a tarball snapshot
- reads the local `package.json` if present
- treats it as an npm package for static analysis

### 5.2 Registry Resolution

Handled by `src/core/registry.ts`.

Current behavior:

- npm:
  - resolves package metadata from `registry.npmjs.org`
  - resolves tarball URL
  - records previous version if available
  - extracts interesting install scripts
- PyPI:
  - resolves package metadata from `pypi.org`
  - resolves source distribution URL when possible
  - install script detection is not applicable in the same way as npm

### 5.3 Triage

Handled by `src/agents/triage-agent.ts`.

Triage chooses whether to run:

- sandbox
- deobfuscator
- behavior diff

Triage inputs include:

- install scripts
- publish date
- previous version
- maintainer info
- manifest excerpt
- typosquat result

If AI is unavailable, triage falls back to deterministic heuristics.

### 5.4 Static Analysis Subsystems

#### IOC Matcher

Files:

- `src/subsystems/ioc-matcher/index.ts`
- `src/subsystems/ioc-matcher/rules/generic.ts`
- `src/subsystems/ioc-matcher/rules/shai-hulud.ts`
- `src/subsystems/ioc-matcher/c2-domains.ts`

What it does:

- matches known malicious filenames
- matches suspicious content regexes
- matches known malicious domains
- matches known compromised versions
- inspects install scripts

Important note:

- the IOC matcher was tuned to avoid a PyPI false positive from overly generic literal-IP matching in benign Python files
- literal IP matching is now restricted to executable-like files and `package.json`

#### Deobfuscator

Files:

- `src/subsystems/deobfuscator/pipeline.ts`
- `src/subsystems/deobfuscator/suspicion-scorer.ts`
- visitor modules under `src/subsystems/deobfuscator/`

What it does:

- iterative AST deobfuscation passes
- string decoding
- constant folding
- eval unwrapping
- wrapper inlining
- sink discovery

Output includes:

- suspicion score
- revealed sinks
- revealed strings
- revealed URLs

#### Behavior Diff

Files:

- `src/subsystems/behavior-diff/index.ts`
- `src/subsystems/behavior-diff/ast-fingerprint.ts`
- `src/subsystems/behavior-diff/capability-diff.ts`

What it does:

- compares the current version with the previous version
- fingerprints capabilities
- detects added and removed capabilities
- detects file changes
- detects install script changes

Important note:

- behavior diff is currently npm-oriented
- when no previous version exists, diff returns a minimal result

#### Typosquat Detection

Files:

- `src/subsystems/typosquat/index.ts`
- `src/subsystems/typosquat/keyboard-distance.ts`
- `src/subsystems/typosquat/popular-packages.ts`

What it does:

- checks package names against popular npm packages
- computes edit-distance style risk
- provides target package suggestions

Important note:

- typosquat detection is currently only applied to npm packages

### 5.5 Dynamic Analysis

Files:

- `src/subsystems/sandbox/docker-manager.ts`
- `src/subsystems/sandbox/strace-parser.ts`
- `src/subsystems/sandbox/behavior-model.ts`
- `docker/Dockerfile.sandbox`
- `docker/entrypoint.sh`
- `docker/seccomp-husk.json`

What it does:

- builds an ephemeral Docker sandbox
- installs the package in Linux
- traces behavior with `strace`
- extracts events such as:
  - network attempts
  - file writes
  - process spawns
  - env access
- classifies suspicious dynamic behavior

Important notes:

- sandboxing requires Docker Desktop
- sandbox support is currently npm-oriented
- dynamic analysis only runs when Docker and the `husk-sandbox` image are ready

### 5.6 Verdict and Recommendations

Handled by `src/agents/verdict-agent.ts`.

The verdict agent:

- scores IOC matches
- scores sandbox findings
- scores deobfuscation output
- scores behavior diff changes
- scores typosquat signals

It returns:

- verdict: `CLEAN`, `SUSPICIOUS`, or `MALICIOUS`
- confidence
- ordered reasons
- actionable recommendations

Examples of recommendations:

- use the legitimate target package instead of the typosquat
- rotate exposed credentials
- audit `.github/workflows`
- inspect the package with `--ignore-scripts`
- pin a previous known-good version when appropriate

### 5.7 Policy Decision

Handled by `src/core/policy.ts`.

This is a major product feature added after the initial scanner implementation.

Policy converts a scan result into:

- `ALLOW`
- `WARN`
- `BLOCK`

Policy reasons can include:

- package verdict threshold
- critical IOC presence
- secret exposure
- workflow tampering
- typosquat distance

Default policy behavior:

- `MALICIOUS` => `BLOCK`
- `SUSPICIOUS` => `WARN`
- `CLEAN` => `ALLOW`

Additional block conditions:

- critical IOCs
- credential exposure indicators
- workflow tampering
- close typosquats

Example policy file:

- `husk.policy.example.json`

Custom policy loading order:

1. `HUSK_POLICY_PATH`
2. `./husk.policy.json`
3. `./.husk/policy.json`
4. built-in default policy

### 5.8 AI Workflow

Handled by:

- `src/agents/ai-workflow.ts`
- `src/agents/triage-agent.ts`
- `src/agents/dynamic-agent.ts`
- `src/agents/reporter-agent.ts`

Supported providers:

- OpenAI
- OpenRouter

Current behavior:

- OpenAI uses the Responses API
- OpenRouter uses chat completions
- OpenRouter has stage-aware fallback models
- AI is used for:
  - triage
  - dynamic narration
  - report writing
- if AI fails or no key is available, Husk falls back to deterministic behavior

Important implementation detail:

- OpenRouter fallback is important because some model/route combinations can return empty output
- the current stable fallback chain includes `openai/gpt-4.1-mini` and `openrouter/auto`

## 6. Guarded Install Workflow

Handled by `src/cli/guarded-install.ts`.

This is one of the biggest changes from "scanner" to "dependency gate."

`planGuardedInstall()`:

- runs full Husk analysis for each requested package
- aggregates verdicts
- derives an overall action:
  - `BLOCK` if any package blocks
  - `WARN` if none block but at least one warns
  - `ALLOW` otherwise
- constructs the underlying package-manager command

`executeGuardedInstall()`:

- blocks execution when policy says `BLOCK`, unless `--force`
- prompts on `WARN`, unless `--yes` or `--force`
- executes the actual install command only after decision

Current underlying install commands:

- npm: `npm install <packages...>`
- pip: `python3 -m pip install <packages...>` by default

Override:

- set `HUSK_PIP_COMMAND` to change pip execution behavior

## 7. npm Interception Workflow

Handled by `src/cli/intercept.ts`.

What it does:

- starts a local Express-based npm registry proxy
- rewrites upstream metadata tarballs to point back through Husk
- downloads the tarball to a temp file
- scans it with the orchestrator
- if policy is `BLOCK`, returns HTTP `403`
- otherwise forwards the original tarball

Headers added on allow path:

- `x-husk-policy-action`
- `x-husk-verdict`

This means npm interception and CLI guarded installs now share the same allow/warn/block logic.

## 8. Dashboard

Files:

- `src/dashboard/server.ts`
- `src/dashboard/public/index.html`
- `src/dashboard/public/app.js`
- `src/dashboard/public/styles.css`

What it provides:

- REST scan endpoint
- SSE stream
- recent verdict history
- stats summary
- modal for blocked packages

Current dashboard behavior:

- reflects verdicts and policy summaries
- shows recommendations and advisories
- works as a live demo surface

Current implementation detail:

- this is an Express + static SPA dashboard
- it is not a Next.js app

## 9. Benchmarking

Files:

- `benchmark/loader.ts`
- `benchmark/runner.ts`
- `benchmark/report.ts`

What it does:

- loads malicious samples from:
  - DataDog malicious packages dataset
  - Backstabbers Knife Collection
- extracts encrypted zip samples using password `infected`
- runs static-only benchmark cases
- uses top popular npm packages as benign sample set
- writes Markdown and JSON benchmark artifacts

Important note:

- benchmark mode is static-only for practicality and reproducibility

## 10. Tests

Current test files:

- `test/ai-workflow.test.ts`
- `test/guarded-install.test.ts`
- `test/policy.test.ts`
- `test/ioc-matcher.test.ts`
- `test/integration/deobfuscator.test.ts`
- `test/integration/e2e.test.ts`
- `test/integration/sandbox.test.ts`

What is covered:

- provider configuration resolution
- guarded install command generation
- policy engine behavior
- IOC matcher tuning for false-positive reduction
- malicious vs benign integration behavior
- sandbox traces
- deobfuscator behavior

`test/setup.ts` clears AI provider env vars so tests stay deterministic.

## 11. Environment Variables

### 11.1 Provider selection

- `AI_PROVIDER`
  - `openai`
  - `openrouter`
  - unset / auto

### 11.2 OpenRouter

- `OPENROUTER_API_KEY`
- `OPENROUTER_MODEL`
- `OPENROUTER_MODEL_DYNAMIC`
- `OPENROUTER_MODEL_REPORTER`
- `OPENROUTER_MODEL_FALLBACKS`
- `OPENROUTER_MODEL_TRIAGE_FALLBACKS`
- `OPENROUTER_MODEL_DYNAMIC_FALLBACKS`
- `OPENROUTER_MODEL_REPORTER_FALLBACKS`
- `OPENROUTER_HTTP_REFERER`
- `OPENROUTER_APP_TITLE`

### 11.3 OpenAI

- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OPENAI_MODEL_DYNAMIC`
- `OPENAI_MODEL_REPORTER`
- provider-specific fallback envs are also supported

### 11.4 Shared AI knobs

- `AI_MODEL`
- `AI_MODEL_TRIAGE`
- `AI_MODEL_DYNAMIC`
- `AI_MODEL_REPORTER`
- `AI_MODEL_FALLBACKS`
- `AI_MODEL_TRIAGE_FALLBACKS`
- `AI_MODEL_DYNAMIC_FALLBACKS`
- `AI_MODEL_REPORTER_FALLBACKS`
- `AI_MAX_RETRIES`
- `AI_RETRY_BASE_MS`

### 11.5 Policy and runtime

- `HUSK_POLICY_PATH`
- `HUSK_PIP_COMMAND`
- `PORT`

## 12. Setup and Verification

Recommended setup:

```bash
npm install
set -a
source .env
set +a
npm run setup
npm run build
```

Recommended verification:

```bash
npm test
node dist/cli/index.js scan --local test/fixtures/malicious/sample1 --json
node dist/cli/index.js scan --local test/fixtures/benign/sample1 --json
node dist/cli/index.js decide npm ./test/fixtures/malicious/sample1 --json
node dist/cli/index.js install npm ./test/fixtures/benign/sample1 --dry-run
```

To install the CLI globally in the current shell environment:

```bash
npm link
```

## 13. Current Strengths

Husk is currently strongest in these areas:

- npm package scanning
- explainable verdicts
- AI-assisted but deterministic-safe workflow
- policy-driven dependency decisions
- actionable remediation output
- npm interception demo path
- hackathon demo readiness

## 14. Current Limitations

This section is intentionally explicit so future work does not oversell the repo.

### 14.1 It is not a shell-wide security layer

Husk does not inspect every terminal command. It only affects:

- direct Husk commands
- npm installs through Husk intercept

### 14.2 It is not a full multi-ecosystem transparent firewall yet

Current state:

- npm guarded install: yes
- npm transparent intercept: yes
- pip guarded install: yes
- pip transparent intercept: no

### 14.3 Dynamic sandboxing is npm-first

Current state:

- Docker sandbox exists
- Linux/strace-based
- best suited to npm install lifecycle behavior

### 14.4 Behavior diff and typosquat are npm-centered

PyPI currently does not get the same maturity level for:

- previous-version behavior diff
- typosquat scoring

### 14.5 Dashboard metric semantics are simple

The live dashboard stat named "false positive rate" is currently derived from dashboard history and suspicious counts, not from benchmark-labeled truth at runtime.

### 14.6 AI is optional

If the provider fails:

- triage/reporting/narration fall back
- core detection still works

## 15. Major Recent Changes

The most important implementation changes added during the latest development pass are:

1. OpenRouter made functional end to end with fallback models
2. Actionable safe-next-move recommendations added to verdicts and advisories
3. Policy engine added to convert scan results into `ALLOW` / `WARN` / `BLOCK`
4. `husk decide` added
5. `husk install` added
6. npm interception updated to block based on policy, not only raw verdict
7. PyPI guarded-install path added
8. IOC matcher tuned to avoid one category of PyPI false positives

## 16. File Map for Fast Navigation

### Product entry points

- `src/cli/index.ts`
- `src/cli/guarded-install.ts`
- `src/cli/intercept.ts`
- `src/dashboard/server.ts`

### Core runtime

- `src/agents/orchestrator.ts`
- `src/core/package-fetcher.ts`
- `src/core/registry.ts`
- `src/core/policy.ts`
- `src/core/types.ts`

### Analysis subsystems

- `src/subsystems/ioc-matcher/index.ts`
- `src/subsystems/deobfuscator/pipeline.ts`
- `src/subsystems/behavior-diff/index.ts`
- `src/subsystems/sandbox/docker-manager.ts`
- `src/subsystems/typosquat/index.ts`

### AI layers

- `src/agents/ai-workflow.ts`
- `src/agents/triage-agent.ts`
- `src/agents/dynamic-agent.ts`
- `src/agents/reporter-agent.ts`
- `src/agents/verdict-agent.ts`

### Evaluation and fixtures

- `benchmark/runner.ts`
- `benchmark/loader.ts`
- `test/`

## 17. Recommended Future Priorities

If continuing the project, the highest-value next steps are:

1. Add true pip interception or package-index proxying
2. Add agent-facing integration mode for CI or coding agents
3. Add organization policy packs and allowlists
4. Add better PyPI-specific heuristics and diffing
5. Add deeper safe-version recommendation logic
6. Add richer benchmark reporting in dashboard
7. Add shell wrapper mode for package-manager commands

## 18. Short Summary

Husk today is best understood as:

An explainable dependency security gate with npm interception, guarded installs, AI-assisted triage/reporting, and machine-readable policy decisions.

It is no longer just a scanner. It is a decision layer for dependency installs.
