import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { glob } from "glob";

import type { DeobfuscationResult } from "../core/types.js";
import { DeobfuscationPipeline } from "../subsystems/deobfuscator/pipeline.js";

const PER_FILE_TIMEOUT_MS = 4_000;
const MAX_FILE_BYTES = 250_000;

/**
 * Files we never bother analyzing because they're false-positive factories:
 *   - `.d.ts`            : TypeScript declaration files contain no executable
 *                          code, only type information. The IOC matcher and
 *                          deobfuscator have no business looking at them
 *                          (e.g. dns.d.ts in @types/node was scoring 99%).
 *   - `*.min.*`          : minified production bundles always look obfuscated
 *                          to a heuristic scorer. mongodb / react / lodash
 *                          all flagged as "high obfuscation" because of this.
 *   - `*.production.*`   : same as above for some build conventions.
 *   - `*.umd.*`          : universal module definitions are a packaging
 *                          format used by legitimate libraries; treated as
 *                          minified bundles to avoid the same false positive.
 *   - `*.map`            : source maps are data, not code.
 *   - `dist/`, `build/`  : already excluded but kept here for clarity.
 */
const NEVER_ANALYZE = [
  "**/*.d.ts",
  "**/*.min.js",
  "**/*.min.cjs",
  "**/*.min.mjs",
  "**/*.production.min.js",
  "**/*.production.js",
  "**/*.umd.js",
  "**/*.umd.cjs",
  "**/*.umd.min.js",
  "**/*.bundle.js",
  "**/*.bundle.cjs",
  "**/*.bundle.mjs",
  // Files prefixed with `_` in lib/ are TypeScript's bundled internals
  // (e.g. typescript's lib/_tsserver.js). They're built artifacts even
  // though they aren't formally `.min.js`.
  "**/lib/_*.js",
  "**/lib/_*.cjs",
  "**/lib/_*.mjs",
  "**/*.map",
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**"
];

/**
 * Heuristic for "this file is a bundle even though its name doesn't say so".
 * Three independent signals; firing any one is enough:
 *   1. Single-line file > 1KB (definitive minification).
 *   2. Average line length > 500 (catches semi-minified bundles that kept
 *      occasional newlines).
 *   3. File > 500KB (anything that large that the package ships is almost
 *      always a bundled artifact, not handwritten code worth analyzing).
 * Catches typescript's lib/_tsserver.js and similar fall-through bundles.
 */
function looksMinified(content: string): boolean {
  if (content.length < 1024) return false;
  if (content.length > 500_000) return true;
  const lines = content.split("\n");
  if (lines.length === 1) return true;
  const avgLineLength = content.length / lines.length;
  return avgLineLength > 500;
}

export class DeobfuscatorAgent {
  private readonly pipeline = new DeobfuscationPipeline();

  async analyzePackage(packagePath: string): Promise<DeobfuscationResult | undefined> {
    const files = await glob("**/*.{js,cjs,mjs,ts,tsx}", {
      cwd: packagePath,
      nodir: true,
      dot: true,
      ignore: NEVER_ANALYZE
    });

    let best: DeobfuscationResult | undefined;
    for (const file of files.slice(0, 25)) {
      const content = await readFile(join(packagePath, file), "utf8").catch(() => "");
      if (!content || content.length > MAX_FILE_BYTES) continue;
      if (looksMinified(content)) continue;

      let result: DeobfuscationResult;
      try {
        result = await Promise.race([
          this.pipeline.deobfuscate(content),
          new Promise<DeobfuscationResult>((_, reject) =>
            setTimeout(() => reject(new Error("deobfuscator-timeout")), PER_FILE_TIMEOUT_MS)
          )
        ]);
      } catch {
        continue;
      }

      result.sourceFile = file;
      if (!best || result.suspicionScore > best.suspicionScore) {
        best = result;
      }
    }

    return best;
  }
}
