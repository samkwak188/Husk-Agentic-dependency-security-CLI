import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import dotenv from "dotenv";

/**
 * Absolute path to the Husk project root, derived from this module's own
 * URL. Survives the CLI being invoked from any cwd (e.g. `~`, `/tmp`, a
 * downstream user's project), unlike `process.cwd()`.
 *
 * In production, this module is at `<root>/dist/core/project-root.js`,
 * so going up two levels gets us back to the project root. In dev (tsx),
 * the source path is `<root>/src/core/project-root.ts`, same depth.
 */
export const PROJECT_ROOT = fileURLToPath(new URL("../..", import.meta.url));

/**
 * Load the project's `.env` from PROJECT_ROOT (NOT from cwd). This is what
 * makes `husk scan ...` work the same whether you run it from `~`, `/tmp`,
 * or the project directory itself — the user only configures one `.env`,
 * and it's always honored.
 *
 * `override: false` means env vars set by the parent shell (e.g. CI
 * pipelines that inject `OPENROUTER_API_KEY` directly) take precedence
 * over the .env file, which is the conventional behavior.
 *
 * Importing this module triggers the load as a side effect, so any module
 * that depends on env vars at import time (e.g. AI workflow clients) will
 * see them as long as it imports `project-root.js` or imports a module
 * that already did.
 */
const envPath = join(PROJECT_ROOT, ".env");
if (existsSync(envPath)) {
  // `quiet: true` suppresses dotenv v17+'s "injected env" tip line so the
  // CLI's own banner stays the first thing the user sees.
  dotenv.config({ path: envPath, override: false, quiet: true });
}

/**
 * Resolve a project-relative path to an absolute path anchored at
 * PROJECT_ROOT, regardless of cwd. Useful for finding bundled assets like
 * `husk.policy.json` or the `datasets/` directory.
 */
export function projectPath(...segments: string[]): string {
  return resolve(PROJECT_ROOT, ...segments);
}

/**
 * The directory the CLI is "operating on" — usually `process.cwd()`, but
 * exposed here so callers don't have to invoke `process.cwd()` directly
 * (and so we have one place to override for testing). This is the right
 * choice for things that genuinely SHOULD be cwd-relative: scanning a
 * local package directory, finding a project's package.json, etc.
 */
export function operatingCwd(): string {
  return process.cwd();
}

// Re-export for convenience so callers can do
//   import { dirname } from "node:path";
// without an unused-import warning if they only need this:
export { dirname };
