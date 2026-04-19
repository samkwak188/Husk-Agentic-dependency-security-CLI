import { stat } from "node:fs/promises";
import { join } from "node:path";

import { glob } from "glob";

import type { PackageMetadata, PackageShapeResult } from "../../core/types.js";

/**
 * Files that count toward "real source code" for the purposes of detecting
 * empty-stub packages. We deliberately exclude type-only files, build
 * artifacts, minified bundles, source maps, and config — none of those
 * indicate that the package actually does something.
 */
const SOURCE_GLOB = "**/*.{js,cjs,mjs,ts,tsx,jsx}";
const SOURCE_IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/*.d.ts",
  "**/*.min.js",
  "**/*.min.cjs",
  "**/*.min.mjs",
  "**/*.umd.js",
  "**/*.bundle.js",
  "**/*.map",
  "**/test/**",
  "**/tests/**",
  "**/__tests__/**",
  "**/spec/**",
  "**/specs/**",
  "**/*.test.*",
  "**/*.spec.*"
];

/**
 * Threshold below which a package is considered "essentially empty".
 * Carefully calibrated against legitimate small packages:
 *   - is-array (npm)         : ~120 B
 *   - is-string (npm)        : ~280 B
 *   - left-pad (npm)         : ~430 B
 *   - noop (npm)             : ~30 B  (literally `module.exports = function(){}`)
 *   - just-a-function (npm)  : ~180 B
 *
 * These legitimate small packages all have well-known maintainers and
 * established names, so the EMPTY signal alone never fires SUSPICIOUS;
 * it only contributes when combined with a suspicious-name signal.
 */
const EMPTY_THRESHOLD_BYTES = 1500;

/**
 * Lexical signals that, when found in a package name, indicate the name
 * was chosen for an attack rather than for a legitimate utility. None of
 * these match popular packages (validated against POPULAR_PACKAGES on
 * 2026-04-19). Word-boundary matched on `-` / `_` separators so we don't
 * accidentally flag substrings (e.g. "test" inside "fastest-validator").
 */
const SUSPICIOUS_NAME_TOKENS = new Set([
  "poc",
  "exploit",
  "payload",
  "backdoor",
  "stealer",
  "miner",
  "drain",
  "drainer",
  "exfil",
  "exfiltrate",
  "rce",
  "shell",
  "reverse",
  "implant",
  "trojan",
  "rootkit",
  "keylog",
  "keylogger",
  "sploit"
]);

/**
 * Numeric-prefix pattern (e.g. `0vulns-...`, `1kzr`, `4m-clean-...`).
 * Many dependency-confusion drops use this style because it's how some
 * internal artifact registries number releases. Almost no legitimate
 * popular package starts with a digit immediately followed by letters.
 */
const NUMERIC_PREFIX_PATTERN = /^\d+[a-z]+/i;

/**
 * "Pristine attack stub" wording — names that explicitly advertise
 * themselves as empty / clean / placeholder, which is a counter-intuitive
 * but real attacker tactic ("clean shopify app", "pristine stripe sdk",
 * etc.) used to make the package look harmless during cursory review.
 */
const PRISTINE_NAME_PATTERN = /\b(clean|pristine|empty|placeholder|stub|sample|demo|fake)\b/i;

function tokenize(name: string): string[] {
  // Strip a scope prefix (`@scope/`) and split on `-`, `_`, `/` so that
  // word-boundary matching sees discrete tokens.
  const stripped = name.replace(/^@[^/]+\//, "");
  return stripped.toLowerCase().split(/[-_/]/).filter(Boolean);
}

async function walkSources(packagePath: string): Promise<string[]> {
  return glob(SOURCE_GLOB, {
    cwd: packagePath,
    nodir: true,
    dot: false,
    ignore: SOURCE_IGNORE
  });
}

async function sumSourceBytes(packagePath: string, files: string[]): Promise<number> {
  let total = 0;
  for (const file of files) {
    try {
      const s = await stat(join(packagePath, file));
      total += s.size;
    } catch {
      // ignore unreadable files
    }
  }
  return total;
}

async function hasReadmeFile(packagePath: string): Promise<boolean> {
  const readmes = await glob("README*", {
    cwd: packagePath,
    nodir: true,
    dot: false,
    nocase: true
  });
  if (readmes.length === 0) return false;
  // Empty README files don't count as "documentation"; they're a known
  // dependency-confusion signature (auto-generated empty placeholder).
  for (const r of readmes) {
    try {
      const s = await stat(join(packagePath, r));
      if (s.size > 200) return true;
    } catch {
      // continue
    }
  }
  return false;
}

function detectSuspiciousNameSignals(name: string): string[] {
  const signals: string[] = [];
  const tokens = tokenize(name);
  const matchedTokens = tokens.filter((t) => SUSPICIOUS_NAME_TOKENS.has(t));
  if (matchedTokens.length > 0) {
    signals.push(`attack-keyword:${matchedTokens.join(",")}`);
  }
  if (NUMERIC_PREFIX_PATTERN.test(name)) {
    signals.push("numeric-prefix");
  }
  if (PRISTINE_NAME_PATTERN.test(name)) {
    signals.push("pristine-stub-keyword");
  }
  return signals;
}

/**
 * Public entry point. Returns a structural fingerprint of the package
 * with a `signal` level that the verdict-agent can act on:
 *   - "none"        : nothing notable (most packages)
 *   - "info"        : empty source but established package, just FYI
 *   - "suspicious"  : empty source AND suspicious name signals — fire the
 *                     dependency-confusion alert
 */
export async function analyzePackageShape(
  packagePath: string,
  metadata: PackageMetadata
): Promise<PackageShapeResult> {
  const files = await walkSources(packagePath);
  const totalSourceBytes = await sumSourceBytes(packagePath, files);
  const hasReadme = await hasReadmeFile(packagePath);

  const isEssentiallyEmpty = totalSourceBytes <= EMPTY_THRESHOLD_BYTES;
  const hasMeaningfulCode = !isEssentiallyEmpty;
  const suspiciousNameSignals = detectSuspiciousNameSignals(metadata.name);

  let signal: PackageShapeResult["signal"] = "none";
  let reason = "";

  if (isEssentiallyEmpty && suspiciousNameSignals.length > 0) {
    signal = "suspicious";
    reason = `Package ships ${totalSourceBytes} B of source across ${files.length} file${files.length === 1 ? "" : "s"} and the name carries dependency-confusion signals (${suspiciousNameSignals.join(", ")}). Pattern matches public-registry stubs used to hijack internal package resolution.`;
  } else if (isEssentiallyEmpty && !hasReadme) {
    signal = "suspicious";
    reason = `Package ships only ${totalSourceBytes} B of source across ${files.length} file${files.length === 1 ? "" : "s"} and has no README. Empty packages with no documentation are a known dependency-confusion attack pattern — no code to detect statically, but the *shape* is suspicious.`;
  } else if (isEssentiallyEmpty) {
    signal = "info";
    reason = `Package is unusually small (${totalSourceBytes} B across ${files.length} file${files.length === 1 ? "" : "s"}) but has documentation, so it's likely a legitimate utility package.`;
  }

  return {
    totalSourceBytes,
    jsFileCount: files.length,
    hasReadme,
    hasMeaningfulCode,
    suspiciousNameSignals,
    signal,
    reason
  };
}
