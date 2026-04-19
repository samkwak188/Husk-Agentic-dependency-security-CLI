// Side-effect import: loads .env from the project root regardless of cwd,
// so the daemon (which runs detached, possibly with a different cwd) sees
// the same OPENROUTER_API_KEY / OPENAI_API_KEY the user configured.
import "../core/project-root.js";

import { execSync, spawn } from "node:child_process";
import { appendFile, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createWriteStream, existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { basename, join, resolve } from "node:path";
import { homedir, tmpdir } from "node:os";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";

import express from "express";

import { HuskOrchestrator } from "../agents/orchestrator.js";
import type { HuskVerdict } from "../core/types.js";
import { box, padVisible, visibleWidth } from "./ui.js";

export const DEFAULT_PORT = 4873;

/**
 * State files (pid, tty path, decision log) live in the USER'S home directory,
 * not in cwd. There is only one intercept proxy per machine (it binds a single
 * port), so its bookkeeping must be addressable regardless of which directory
 * the user invoked the CLI from. The previous cwd-based layout caused this
 * exact bug: running `husk intercept --enable` from `~` couldn't see the
 * orphan daemon registered under `<project>/.husk/intercept.pid`, so it
 * "started" a new daemon that immediately died (no node_modules in `~`)
 * while the orphan kept serving requests with a dead TTY config.
 */
const HUSK_HOME = join(homedir(), ".husk");
const PID_FILE = join(HUSK_HOME, "intercept.pid");
const LOG_FILE = join(HUSK_HOME, "intercept.log");
const TTY_FILE = join(HUSK_HOME, "intercept.tty");

/**
 * Project root, resolved from this module's own URL — survives the daemon
 * being spawned from any cwd. Used to locate `tsx` and the daemon's source
 * file when respawning. Walks up from `<project>/dist/cli/intercept.js`
 * (production) or `<project>/src/cli/intercept.ts` (tsx mode).
 */
const PROJECT_ROOT = fileURLToPath(new URL("../..", import.meta.url));

export function getInterceptLogPath(): string {
  return LOG_FILE;
}

/**
 * Resolve the path to the user's controlling TTY in the *parent* shell that
 * invoked `husk intercept --enable`. We can't ask the daemon for this — it's
 * spawned with `detached: true` + `stdio: "ignore"` and therefore has no
 * controlling terminal of its own. We capture it before forking.
 *
 * On macOS/Linux, `tty` prints the path bound to stdin (e.g. `/dev/ttys003`).
 * Returns null if stdin isn't a TTY (e.g. the CLI was piped) or the lookup
 * fails for any reason.
 */
function captureControllingTty(): string | null {
  if (process.platform === "win32") return null;
  if (!process.stdin.isTTY) return null;
  try {
    const out = execSync("tty", { stdio: ["inherit", "pipe", "ignore"] })
      .toString()
      .trim();
    if (!out || out === "not a tty" || !out.startsWith("/dev/")) return null;
    return out;
  } catch {
    return null;
  }
}

async function ensureDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
}

async function ensureFile(path: string): Promise<void> {
  try {
    await stat(path);
  } catch {
    await writeFile(path, "", "utf8");
  }
}

function buildRegistryLine(port: number): string {
  return `registry=http://localhost:${port}`;
}

async function updateNpmrc(enable: boolean, port = DEFAULT_PORT): Promise<void> {
  const npmrcPath = resolve(".npmrc");
  await ensureFile(npmrcPath);
  const current = await readFile(npmrcPath, "utf8");
  const lines = current
    .split(/\r?\n/)
    .filter(Boolean)
    .filter((line) => !line.startsWith("registry=http://localhost:"));

  if (enable) {
    lines.push(buildRegistryLine(port));
  }

  await writeFile(npmrcPath, `${lines.join("\n")}${lines.length ? "\n" : ""}`, "utf8");
}

async function readPid(): Promise<number | null> {
  try {
    const content = await readFile(PID_FILE, "utf8");
    return Number(content.trim()) || null;
  } catch {
    return null;
  }
}

async function writePid(pid: number): Promise<void> {
  await ensureDirectory(HUSK_HOME);
  await writeFile(PID_FILE, String(pid), "utf8");
}

async function downloadToFile(url: string, destination: string): Promise<void> {
  const response = await fetch(url, {
    headers: {
      "user-agent": "husk-intercept/0.1.0"
    }
  });

  if (!response.ok || !response.body) {
    throw new Error(`Failed to fetch upstream tarball ${url}`);
  }

  const payload = Buffer.from(await response.arrayBuffer());
  await writeFile(destination, payload);
}

function extractPackageSpecFromTarballUrl(url: string): string {
  const match = url.match(/\/__husk_tarball__\/(?<name>[^/]+)\/(?<version>[^/?#]+)/);
  if (!match?.groups?.name || !match.groups.version) {
    return "unknown@unknown";
  }

  return `${decodeURIComponent(match.groups.name)}@${decodeURIComponent(match.groups.version)}`;
}

function rewriteMetadataTarballs(payload: string, port: number): string {
  try {
    const parsed = JSON.parse(payload) as Record<string, unknown>;
    const versions = parsed.versions as Record<string, Record<string, unknown>> | undefined;
    if (!versions) {
      return payload;
    }

    const packageName = typeof parsed.name === "string" ? parsed.name : "";
    for (const [version, versionData] of Object.entries(versions)) {
      const dist = (versionData.dist as Record<string, unknown> | undefined) ?? {};
      const tarball = typeof dist?.tarball === "string" ? dist.tarball : undefined;
      if (!tarball) {
        continue;
      }

      dist.tarball = `http://localhost:${port}/__husk_tarball__/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}?upstream=${encodeURIComponent(
        tarball
      )}`;
      versionData.dist = dist;
    }

    return JSON.stringify(parsed);
  } catch {
    return payload;
  }
}

interface TakedownSignal {
  packageName: string;
  unpublishedVersions: string[];
  unpublishedAt?: string;
  fullPackageUnpublishedAt?: string;
  securityPlaceholderVersion?: string;
  latest?: string;
}

/**
 * Inspect a metadata document for registry-takedown signals. npm's metadata
 * embeds an `unpublished` record under `time` when a whole package is
 * withdrawn, lists per-version timestamps in `time` while removing the
 * version from `versions` when individual versions are pulled, and points
 * `dist-tags.latest` at a `*-security` placeholder when the registry
 * replaces the package with a takedown stub. We surface all three.
 */
function detectTakedownSignals(payload: string): TakedownSignal | null {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(payload) as Record<string, unknown>;
  } catch {
    return null;
  }

  const packageName = typeof parsed.name === "string" ? parsed.name : "";
  if (!packageName) return null;

  const versions = (parsed.versions as Record<string, unknown> | undefined) ?? {};
  const time = (parsed.time as Record<string, unknown> | undefined) ?? {};
  const distTags = (parsed["dist-tags"] as Record<string, unknown> | undefined) ?? {};
  const latest = typeof distTags.latest === "string" ? distTags.latest : undefined;

  const RESERVED_TIME_KEYS = new Set(["created", "modified", "unpublished"]);
  const unpublishedVersions: string[] = [];
  for (const key of Object.keys(time)) {
    if (RESERVED_TIME_KEYS.has(key)) continue;
    if (!(key in versions)) unpublishedVersions.push(key);
  }

  const unpublishedRecord = time.unpublished as Record<string, unknown> | undefined;
  const fullPackageUnpublishedAt =
    typeof unpublishedRecord?.time === "string" ? unpublishedRecord.time : undefined;

  const securityPlaceholderVersion =
    latest && /-security(?:$|[.\-])/.test(latest) && Object.keys(versions).length <= 1
      ? latest
      : undefined;

  if (
    unpublishedVersions.length === 0 &&
    !fullPackageUnpublishedAt &&
    !securityPlaceholderVersion
  ) {
    return null;
  }

  // Pick the most recent unpublished timestamp we can find for context.
  let unpublishedAt: string | undefined;
  for (const v of unpublishedVersions) {
    const t = time[v];
    if (typeof t === "string" && (!unpublishedAt || t > unpublishedAt)) {
      unpublishedAt = t;
    }
  }

  return {
    packageName,
    unpublishedVersions,
    unpublishedAt,
    fullPackageUnpublishedAt,
    securityPlaceholderVersion,
    latest
  };
}

async function appendInterceptLog(entry: Record<string, unknown>): Promise<void> {
  try {
    await ensureDirectory(HUSK_HOME);
    const line = `${JSON.stringify({ timestamp: new Date().toISOString(), ...entry })}\n`;
    await appendFile(LOG_FILE, line, "utf8");
  } catch {
    // Logging is best-effort; never crash the proxy because of disk issues.
  }
}

/**
 * Resolve the TTY path the daemon should write breadcrumbs to. The daemon is
 * detached and has no controlling terminal of its own, so we use the path
 * captured by the parent CLI when `--enable` ran. Sources, in order:
 *   1. `HUSK_INTERCEPT_TTY` env var (passed by the parent on spawn)
 *   2. `.husk/intercept.tty` (persisted by the parent for re-discovery)
 * Returns null if no usable path exists.
 */
function resolveBreadcrumbTty(): string | null {
  if (process.platform === "win32") return null;
  const fromEnv = process.env.HUSK_INTERCEPT_TTY?.trim();
  if (fromEnv && fromEnv.startsWith("/dev/") && existsSync(fromEnv)) return fromEnv;
  try {
    const fromFile = readFileSync(TTY_FILE, "utf8").trim();
    if (fromFile && fromFile.startsWith("/dev/") && existsSync(fromFile)) return fromFile;
  } catch {
    // no persisted path
  }
  return null;
}

/**
 * Best-effort breadcrumb to the user's controlling TTY. Writes are async and
 * never block the response. No-ops if no captured TTY is available (e.g. the
 * CLI was invoked from a non-interactive context like CI).
 */
/**
 * Best-effort breadcrumb to the user's controlling TTY. Diagnostic events
 * are logged only on failure paths so the operator can troubleshoot when a
 * banner is expected but didn't appear; the success path stays quiet to
 * keep `husk intercept --logs` focused on real security events.
 */
function writeTtyBreadcrumb(message: string): void {
  const ttyPath = resolveBreadcrumbTty();
  if (!ttyPath) return;
  try {
    const stream = createWriteStream(ttyPath, { flags: "a" });
    stream.on("error", (err) => {
      void appendInterceptLog({ event: "tty-breadcrumb-error", ttyPath, error: err.message });
    });
    stream.write(`${message}\n`, (err) => {
      if (err) {
        void appendInterceptLog({
          event: "tty-breadcrumb-write-error",
          ttyPath,
          error: err.message
        });
      }
      stream.end();
    });
  } catch (err) {
    void appendInterceptLog({
      event: "tty-breadcrumb-throw",
      ttyPath,
      error: err instanceof Error ? err.message : String(err)
    });
  }
}

function formatTakedownBreadcrumb(signal: TakedownSignal): string {
  const RED = "\u001b[31m";
  const BOLD = "\u001b[1m";
  const DIM = "\u001b[2m";
  const RESET = "\u001b[0m";

  if (signal.fullPackageUnpublishedAt) {
    return (
      `\n${RED}${BOLD}✗ Husk: registry takedown${RESET} ` +
      `${signal.packageName} was unpublished by the registry on ${signal.fullPackageUnpublishedAt}.\n` +
      `${DIM}  Run \`husk scan ${signal.packageName}\` for the full verdict. ` +
      `Logged to .husk/intercept.log${RESET}`
    );
  }

  if (signal.securityPlaceholderVersion) {
    return (
      `\n${RED}${BOLD}✗ Husk: security placeholder${RESET} ` +
      `${signal.packageName} now resolves to ${signal.securityPlaceholderVersion} — the registry replaced the real package with a takedown stub.\n` +
      `${DIM}  Do NOT install. Run \`husk scan ${signal.packageName}\` for context. ` +
      `Logged to .husk/intercept.log${RESET}`
    );
  }

  const sample = signal.unpublishedVersions.slice(0, 3).join(", ");
  const more =
    signal.unpublishedVersions.length > 3
      ? ` (+${signal.unpublishedVersions.length - 3} more)`
      : "";
  return (
    `\n${RED}${BOLD}✗ Husk: registry takedown${RESET} ` +
    `${signal.packageName} has unpublished versions: ${sample}${more}.\n` +
    `${DIM}  If npm just failed with ETARGET, you likely asked for one of these. ` +
    `Run \`husk scan ${signal.packageName}@<version>\` for the full verdict. ` +
    `Logged to .husk/intercept.log${RESET}`
  );
}

/**
 * Per-process dedupe so npm's repeated metadata fetches during a single
 * install don't spam the TTY/log with the same warning.
 */
const seenTakedowns = new Map<string, number>();
const TAKEDOWN_DEDUPE_MS = 30_000;

function shouldEmitTakedown(packageName: string): boolean {
  const now = Date.now();
  const previous = seenTakedowns.get(packageName);
  if (previous && now - previous < TAKEDOWN_DEDUPE_MS) return false;
  seenTakedowns.set(packageName, now);
  return true;
}

/**
 * Render a `husk scan`-style verdict card for a package the proxy just
 * blocked. We can't pipe this through npm — npm only sees the 403 body —
 * so it goes straight to the user's controlling TTY (the one we captured
 * on `intercept --enable`). The structure intentionally mirrors the scan
 * card: ASCII-only ANSI to keep wrapping deterministic, headline + reason
 * list + recommended next step. ANSI escapes are written raw so the card
 * looks the same whether the user's shell is bash, zsh, or fish.
 */
function formatVerdictBlockCard(spec: string, verdict: HuskVerdict): string {
  const RED = "\u001b[31m";
  const RED_BOLD = "\u001b[31;1m";
  const YELLOW_BOLD = "\u001b[33;1m";
  const VIOLET_BOLD = "\u001b[38;5;141;1m";
  const CYAN_BOLD = "\u001b[36;1m";
  const DIM = "\u001b[2m";
  const RESET = "\u001b[0m";
  const BORDER = (s: string) => `${DIM}${s}${RESET}`;

  const headline = verdict.verdict === "MALICIOUS" ? "DO NOT INSTALL" : "BE CAREFUL";
  const headerColor = verdict.verdict === "MALICIOUS" ? RED_BOLD : YELLOW_BOLD;
  const glyph = verdict.verdict === "MALICIOUS" ? "✗" : "⚠";

  const ecosystem = verdict.ecosystem ?? "npm";
  const left = `${headerColor}${glyph}  ${headline}${RESET}`;
  const right = `${DIM}${ecosystem} ·${RESET} ${CYAN_BOLD}${spec}${RESET}`;
  const innerWidth = 78 - 2 - 4;
  const headerLine = padVisible(
    left + " ".repeat(Math.max(2, innerWidth - visibleWidth(left) - visibleWidth(right))) + right,
    innerWidth
  );

  const lines: string[] = [];
  lines.push(headerLine);
  lines.push("");

  // Reason list: top 3 by severity. Numbered bullets so the user sees how
  // many findings backed up the BLOCK without overflowing the card.
  const severityRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const sortedReasons = (verdict.reasons ?? [])
    .slice()
    .sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0) || b.scoreImpact - a.scoreImpact)
    .slice(0, 3);

  if (sortedReasons.length > 0) {
    lines.push(`${VIOLET_BOLD}Why this verdict${RESET}`);
    sortedReasons.forEach((reason, idx) => {
      const sevColor = reason.severity === "CRITICAL" || reason.severity === "HIGH" ? RED : YELLOW_BOLD;
      lines.push(`${headerColor}${idx + 1}.${RESET} ${sevColor}[${reason.severity}]${RESET} ${reason.title}`);
      const evidence = (reason.evidence ?? "").replace(/\s+/g, " ").trim();
      if (evidence) {
        const truncated = evidence.length > 220 ? `${evidence.slice(0, 219)}…` : evidence;
        lines.push(`   ${DIM}${truncated}${RESET}`);
      }
    });
    lines.push("");
  } else {
    lines.push(`${VIOLET_BOLD}Why this verdict${RESET}`);
    lines.push(`${DIM}Husk policy blocked this install (${verdict.verdict.toLowerCase()}, confidence ${Math.round((verdict.confidence ?? 0) * 100)}%).${RESET}`);
    lines.push("");
  }

  lines.push(`${VIOLET_BOLD}What to do${RESET}`);
  const action = verdict.userAction;
  if (action?.next_step) {
    lines.push(`${headerColor}→${RESET} ${action.next_step}`);
  } else {
    lines.push(`${headerColor}→${RESET} Investigate before installing — this package was blocked by Husk.`);
  }
  const inspectCmd = `husk scan ${spec} --sandbox`;
  lines.push(`${DIM}$${RESET} ${CYAN_BOLD}${inspectCmd}${RESET}   ${DIM}(full verdict + sandbox trace)${RESET}`);
  lines.push(`${DIM}$${RESET} ${CYAN_BOLD}husk intercept --logs${RESET}   ${DIM}(history of all proxy events)${RESET}`);

  // Soften the "intercept blocked" prefix line so the user sees a clear
  // boundary above the npm error that follows. Wrap the whole thing in box().
  const card = box(lines, { width: 78, color: BORDER });
  const banner = `\n${RED_BOLD}✗ Husk blocked ${spec}${RESET}  ${DIM}(npm will print its own ETARGET/E403 below)${RESET}\n`;
  return banner + card.join("\n") + "\n";
}

/**
 * Compact one-line breadcrumb for every package the proxy lets through.
 * Without this the user has no proof Husk actually ran when an install
 * "just works" — they assume intercept silently failed. Format:
 *
 *   ✓ Husk allowed react@18.2.0   clean · conf 30% · 14.2s · IOC ✓ deobf ✓
 *   ⚠ Husk warned express@4.19.2  suspicious · conf 55% · 8.1s — see `husk scan`
 *
 * Designed to be readable in one terminal width (~78 cols), single line.
 */
function formatScannedBreadcrumb(spec: string, verdict: HuskVerdict, scanMs: number): string {
  const GREEN_BOLD = "\u001b[32;1m";
  const YELLOW_BOLD = "\u001b[33;1m";
  const CYAN_BOLD = "\u001b[36;1m";
  const DIM = "\u001b[2m";
  const RESET = "\u001b[0m";

  const isWarn = verdict.verdict === "SUSPICIOUS" || verdict.policy?.action === "WARN";
  const glyph = isWarn ? `${YELLOW_BOLD}⚠${RESET}` : `${GREEN_BOLD}✓${RESET}`;
  const action = isWarn ? "warned" : "allowed";
  const verdictLabel = (verdict.verdict ?? "CLEAN").toLowerCase();
  const confidence = Math.round((verdict.confidence ?? 0) * 100);
  const ms = scanMs >= 1000 ? `${(scanMs / 1000).toFixed(1)}s` : `${Math.round(scanMs)}ms`;

  // Tail: list the subsystems that actually had something to say. Helps the
  // user understand what Husk inspected — not just that it ran.
  const subsystems: string[] = [];
  if ((verdict.iocs ?? []).length > 0) subsystems.push(`IOC ${verdict.iocs.length}`);
  if (verdict.deobfuscation) subsystems.push("deobf ✓");
  if (verdict.behaviorDiff) subsystems.push("behavior ✓");
  if (verdict.sandboxResult) subsystems.push("sandbox ✓");
  if (verdict.typosquat) subsystems.push("typosquat hit");
  const subsystemsTail = subsystems.length > 0 ? `   ${DIM}[${subsystems.join(" · ")}]${RESET}` : "";

  const head = `${glyph} ${DIM}Husk ${action}${RESET} ${CYAN_BOLD}${spec}${RESET}`;
  const stats = `${DIM}${verdictLabel} · conf ${confidence}% · ${ms}${RESET}`;
  const followup = isWarn ? `   ${DIM}— run \`husk scan ${spec}\` for details${RESET}` : "";

  return `${head}   ${stats}${subsystemsTail}${followup}`;
}

async function handleTakedownSignal(signal: TakedownSignal): Promise<void> {
  if (!shouldEmitTakedown(signal.packageName)) return;

  await appendInterceptLog({
    event: "registry-takedown",
    package: signal.packageName,
    latest: signal.latest,
    unpublishedVersions: signal.unpublishedVersions,
    unpublishedAt: signal.unpublishedAt,
    fullPackageUnpublishedAt: signal.fullPackageUnpublishedAt,
    securityPlaceholderVersion: signal.securityPlaceholderVersion
  });

  writeTtyBreadcrumb(formatTakedownBreadcrumb(signal));
}

export async function startInterceptServer(port = DEFAULT_PORT): Promise<void> {
  const app = express();
  const orchestrator = new HuskOrchestrator();

  app.get("/__husk_tarball__/:name/:version", async (request, response) => {
    const upstream = request.query.upstream;
    if (typeof upstream !== "string") {
      response.status(400).json({ error: "Missing upstream tarball URL" });
      return;
    }

    const tempPath = join(tmpdir(), `husk-intercept-${Date.now()}-${basename(upstream) || "pkg.tgz"}`);
    const spec = extractPackageSpecFromTarballUrl(request.originalUrl);
    const startedAt = Date.now();
    try {
      await downloadToFile(upstream, tempPath);
      const verdict = await orchestrator.analyze(spec, { localPath: tempPath });
      const scanMs = Date.now() - startedAt;

      if (verdict.policy.action === "BLOCK") {
        // Rich verdict card to the user's captured TTY (above the npm 403
        // error). Falls back to logging only if no TTY was captured.
        writeTtyBreadcrumb(formatVerdictBlockCard(spec, verdict));
        void appendInterceptLog({
          event: "blocked",
          package: spec,
          verdict: verdict.verdict,
          confidence: verdict.confidence,
          scanMs,
          topReasons: (verdict.reasons ?? []).slice(0, 3).map((r) => ({
            severity: r.severity,
            title: r.title
          }))
        });
        response.status(403).json({
          error: "Blocked by Husk",
          verdict: { verdict: verdict.verdict, confidence: verdict.confidence, reasons: verdict.reasons }
        });
        return;
      }

      // Allow / Warn path: forward the tarball, but emit a one-line
      // breadcrumb to the user's TTY and log the decision. This is what
      // proves to the user that intercept actually ran instead of npm
      // talking to the registry directly.
      const upstreamResponse = await fetch(upstream);
      if (!upstreamResponse.ok || !upstreamResponse.body) {
        response.status(502).json({ error: "Unable to forward tarball" });
        return;
      }

      writeTtyBreadcrumb(formatScannedBreadcrumb(spec, verdict, scanMs));
      void appendInterceptLog({
        event: verdict.policy.action === "WARN" ? "warned" : "allowed",
        package: spec,
        verdict: verdict.verdict,
        confidence: verdict.confidence,
        scanMs,
        subsystems: {
          iocs: (verdict.iocs ?? []).length,
          deobfuscation: Boolean(verdict.deobfuscation),
          behaviorDiff: Boolean(verdict.behaviorDiff),
          sandbox: Boolean(verdict.sandboxResult),
          typosquat: Boolean(verdict.typosquat)
        }
      });

      response.setHeader("content-type", upstreamResponse.headers.get("content-type") ?? "application/octet-stream");
      response.setHeader("x-husk-policy-action", verdict.policy.action);
      response.setHeader("x-husk-verdict", verdict.verdict);
      response.setHeader("x-husk-confidence", String(verdict.confidence ?? 0));
      response.end(Buffer.from(await upstreamResponse.arrayBuffer()));
    } catch (error) {
      response.status(500).json({
        error: error instanceof Error ? error.message : String(error)
      });
    } finally {
      await rm(tempPath, { force: true }).catch(() => undefined);
    }
  });

  app.use(async (request, response) => {
    const upstreamUrl = `https://registry.npmjs.org${request.originalUrl}`;
    const upstreamResponse = await fetch(upstreamUrl, {
      method: request.method,
      headers: {
        "user-agent": "husk-intercept/0.1.0",
        accept: request.headers.accept ?? "*/*"
      }
    });

    const contentType = upstreamResponse.headers.get("content-type") ?? "";
    response.status(upstreamResponse.status);

    if (contentType.includes("application/json")) {
      const text = await upstreamResponse.text();

      // Surface registry-takedown signals BEFORE forwarding. npm bails at
      // metadata for unpublished versions, so this is the only point where
      // Husk can warn the user about pinned-version takedowns.
      const signal = detectTakedownSignals(text);
      if (signal) {
        // Fire and forget — we don't want to block the metadata response.
        void handleTakedownSignal(signal);
      }

      response.setHeader("content-type", contentType);
      response.setHeader("x-husk-intercept", "active");
      if (signal) response.setHeader("x-husk-takedown", "true");
      response.send(rewriteMetadataTarballs(text, port));
      return;
    }

    if (!upstreamResponse.body) {
      response.end();
      return;
    }

    response.setHeader("content-type", contentType || "application/octet-stream");
    response.end(Buffer.from(await upstreamResponse.arrayBuffer()));
  });

  await new Promise<void>((resolvePromise) => {
    createServer(app).listen(port, () => resolvePromise());
  });
}

export interface EnableInterceptResult {
  port: number;
  pid: number;
  ttyPath: string | null;
  restarted: boolean;
}

/**
 * Kill any process holding `port`, regardless of whether we recorded its
 * PID. This is the defense-in-depth step that protects against the orphan
 * scenario where an earlier `--enable` from a different cwd registered its
 * PID elsewhere (or was force-killed without cleaning up its PID file).
 */
function killProcessOnPort(port: number): boolean {
  try {
    const out = execSync(`lsof -t -i:${port}`, { stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
    if (!out) return false;
    const pids = out.split(/\s+/).map((s) => Number(s)).filter((n) => Number.isFinite(n) && n > 0 && n !== process.pid);
    if (pids.length === 0) return false;
    for (const pid of pids) {
      try {
        process.kill(pid, "SIGTERM");
      } catch {
        // ignore — process might have died between lsof and now
      }
    }
    return true;
  } catch {
    // lsof not available or no listener — both fine
    return false;
  }
}

async function killExistingDaemon(port: number): Promise<boolean> {
  let killedSomething = false;

  // 1. Kill the PID we recorded (if any). Best-effort.
  const pid = await readPid();
  if (pid) {
    try {
      process.kill(pid, 0);
      try {
        process.kill(pid);
        killedSomething = true;
      } catch {
        // already dead
      }
    } catch {
      // PID file is stale
    }
  }

  // 2. Kill anything still holding the port. This catches the case where the
  // PID file is wrong because a previous `--enable` was run from a different
  // cwd and registered its bookkeeping under a different .husk directory.
  if (killProcessOnPort(port)) killedSomething = true;

  if (killedSomething) await new Promise((r) => setTimeout(r, 250));
  await rm(PID_FILE, { force: true }).catch(() => undefined);
  return killedSomething;
}

/**
 * Resolve the entry point to use for the daemon. In production (after `npm
 * run build`), the compiled `dist/cli/intercept.js` is preferred — no tsx
 * needed, faster startup, no extra dependency. We fall back to running the
 * TypeScript source via tsx for development setups where the build may be
 * stale.
 */
function resolveDaemonEntrypoint(): { command: string; args: string[] } {
  const distEntrypoint = join(PROJECT_ROOT, "dist", "cli", "intercept.js");
  if (existsSync(distEntrypoint)) {
    return { command: process.execPath, args: [distEntrypoint] };
  }
  const tsxCli = join(PROJECT_ROOT, "node_modules", "tsx", "dist", "cli.mjs");
  const srcEntrypoint = join(PROJECT_ROOT, "src", "cli", "intercept.ts");
  if (!existsSync(tsxCli) || !existsSync(srcEntrypoint)) {
    throw new Error(
      `Husk intercept daemon entrypoint not found. Looked in:\n  ${distEntrypoint}\n  ${srcEntrypoint} (via ${tsxCli})\nRun \`npm run build\` from ${PROJECT_ROOT}.`
    );
  }
  return { command: process.execPath, args: [tsxCli, srcEntrypoint] };
}

export async function enableIntercept(port = DEFAULT_PORT): Promise<EnableInterceptResult> {
  // Always restart on enable, and always kill anything on the port even if
  // we don't recognize its PID. Without the port-based kill, an orphan from
  // a previous session keeps serving requests with stale code and a dead
  // TTY config — exactly the bug that made install commands silently hit
  // an old daemon while new ones appeared to start successfully.
  const restarted = await killExistingDaemon(port);

  // Capture the parent's controlling TTY so the daemon (which is detached
  // and has none of its own) knows where to write user-visible breadcrumbs.
  const ttyPath = captureControllingTty();
  await ensureDirectory(HUSK_HOME);
  if (ttyPath) {
    await writeFile(TTY_FILE, ttyPath, "utf8");
  } else {
    await rm(TTY_FILE, { force: true }).catch(() => undefined);
  }

  const { command, args } = resolveDaemonEntrypoint();
  const child = spawn(command, [...args, "--serve", "--port", String(port)], {
    cwd: PROJECT_ROOT,
    detached: true,
    stdio: "ignore",
    env: { ...process.env, ...(ttyPath ? { HUSK_INTERCEPT_TTY: ttyPath } : {}) }
  });
  child.unref();
  await writePid(child.pid!);
  await updateNpmrc(true, port);

  return { port, pid: child.pid!, ttyPath, restarted };
}

export async function disableIntercept(): Promise<void> {
  const pid = await readPid();
  if (pid) {
    try {
      process.kill(pid);
    } catch {
      // ignore stale pid
    }
  }
  // Also kill any orphan still bound to the port, regardless of PID file.
  killProcessOnPort(DEFAULT_PORT);

  await rm(PID_FILE, { force: true }).catch(() => undefined);
  await rm(TTY_FILE, { force: true }).catch(() => undefined);
  await updateNpmrc(false);
}

export interface InterceptStatus {
  enabled: boolean;
  pid: number | null;
  port: number;
  logPath: string;
}

export async function getInterceptStatus(port = DEFAULT_PORT): Promise<InterceptStatus> {
  const pid = await readPid();
  let alive = false;
  if (pid) {
    try {
      process.kill(pid, 0);
      alive = true;
    } catch {
      alive = false;
    }
  }
  return { enabled: alive, pid: alive ? pid : null, port, logPath: getInterceptLogPath() };
}

export async function readInterceptLog(limit = 50): Promise<string[]> {
  try {
    const content = await readFile(LOG_FILE, "utf8");
    const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
    return lines.slice(-limit);
  } catch {
    return [];
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const portIndex = args.indexOf("--port");
  const port = portIndex >= 0 ? Number(args[portIndex + 1]) : DEFAULT_PORT;

  if (args.includes("--serve")) {
    await startInterceptServer(port);
    await writePid(process.pid);
    return;
  }

  if (args.includes("--enable")) {
    await enableIntercept(port);
    return;
  }

  if (args.includes("--disable")) {
    await disableIntercept();
    return;
  }
}

// Autorun guard: trigger main() when this module is invoked as a script,
// in either TS (tsx) or compiled JS form. Comparing argv[1] to both
// extensions is robust to which entrypoint resolveDaemonEntrypoint() picks.
const invokedAsScript =
  Boolean(process.argv[1]) &&
  (process.argv[1].endsWith("intercept.ts") || process.argv[1].endsWith("intercept.js"));

if (invokedAsScript) {
  void main();
}
