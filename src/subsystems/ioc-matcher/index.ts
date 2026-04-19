import { readFile } from "node:fs/promises";
import { basename, join, relative } from "node:path";

import { glob } from "glob";

import type { IOCMatch, IOCRule, PackageMetadata } from "../../core/types.js";
import { KNOWN_C2_DOMAINS } from "./c2-domains.js";
import { GENERIC_IOCS } from "./rules/generic.js";
import { SHAI_HULUD_IOCS } from "./rules/shai-hulud.js";

const MAX_FILE_BYTES = 256_000;
const EXECUTABLE_LIKE_EXTENSIONS = [".js", ".cjs", ".mjs", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".ps1"];

/**
 * Files we never read for content rules. Three classes of false-positive
 * traps live here:
 *
 *   1. Type-only / non-code:  `.d.ts` declaration files have no executable
 *      code (e.g. @types/node's dns.d.ts was scoring 99% on DNS rules).
 *   2. Minified bundles:      `*.min.js` / `*.umd.js` / `*.production.*`
 *      systematically false-positive obfuscation and sink-density rules.
 *   3. Documentation / config: README, CHANGELOG, LICENSE, *.md — patterns
 *      that mention `.npmrc`, "credentials", "GitHub workflow", etc. in
 *      docs are not exfiltration. eslint's README was flagging credential
 *      IOCs for exactly this reason.
 *   4. Examples / tests:      every legitimate package ships test fixtures
 *      that demonstrate dangerous APIs. Skipping them avoids flagging the
 *      package on its own example code.
 */
const SKIP_FILE_PATTERNS = [
  // Type-only / minified
  /\.d\.ts$/i,
  /\.min\.[cm]?js$/i,
  /\.production\.min\.js$/i,
  /\.production\.js$/i,
  /\.umd\.[cm]?js$/i,
  /\.map$/i,
  /(^|\/)dist\//i,
  /(^|\/)build\//i,
  // Documentation / config (text-only, often contains pattern-matching IOC keywords)
  /\.(md|markdown|mdx|txt|rst|adoc|asciidoc)$/i,
  /(^|\/)(README|CHANGELOG|HISTORY|LICENSE|LICENCE|NOTICE|AUTHORS|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY)(\.|$)/i,
  /(^|\/)docs?\//i,
  // Examples and tests (legitimate packages ship adversarial-looking fixtures)
  /(^|\/)examples?\//i,
  /(^|\/)samples?\//i,
  /(^|\/)__tests__\//i,
  /(^|\/)(test|tests|spec|specs)\//i,
  /\.(test|spec)\.(c|m)?(j|t)sx?$/i,
  /(^|\/)__fixtures__\//i,
  /(^|\/)fixtures?\//i
];

function shouldSkipFileForContentRules(file: string): boolean {
  return SKIP_FILE_PATTERNS.some((pattern) => pattern.test(file));
}

async function readText(path: string): Promise<string> {
  try {
    const content = await readFile(path, "utf8");
    return content.slice(0, MAX_FILE_BYTES);
  } catch {
    return "";
  }
}

export class IOCMatcher {
  private readonly rules: IOCRule[];

  constructor() {
    this.rules = [...SHAI_HULUD_IOCS, ...GENERIC_IOCS];
  }

  async match(packagePath: string, metadata: PackageMetadata): Promise<IOCMatch[]> {
    const matches: IOCMatch[] = [];
    const files = await glob("**/*", {
      cwd: packagePath,
      dot: true,
      nodir: true,
      ignore: ["node_modules/**", ".git/**"]
    });

    for (const rule of this.rules) {
      if (rule.type === "package_version" && metadata.name === rule.name && rule.versions.includes(metadata.version)) {
        matches.push({
          severity: rule.severity,
          ruleType: rule.type,
          description: rule.description,
          evidence: `${metadata.name}@${metadata.version}`
        });
      }

      if (rule.type === "script_pattern") {
        for (const [scriptName, scriptBody] of Object.entries(metadata.installScripts)) {
          if (rule.pattern.test(`${scriptName}: ${scriptBody}`)) {
            matches.push({
              severity: rule.severity,
              ruleType: rule.type,
              description: rule.description,
              evidence: `${scriptName}: ${scriptBody}`
            });
          }
        }
      }
    }

    for (const file of files) {
      const absolutePath = join(packagePath, file);
      const filename = basename(file);
      // Filename rules still apply (a malicious filename is a malicious
      // filename) but content/regex/domain inspection is skipped for
      // type-only / minified files where false positives are guaranteed.
      const skipContent = shouldSkipFileForContentRules(file);
      const content = skipContent ? "" : await readText(absolutePath);

      for (const rule of this.rules) {
        if (rule.type === "filename" && (file.includes(rule.pattern) || filename === rule.pattern)) {
          matches.push({
            severity: rule.severity,
            ruleType: rule.type,
            description: rule.description,
            evidence: relative(packagePath, absolutePath),
            file
          });
        }

        if (rule.type === "content_regex" && content && this.shouldEvaluateContentRule(rule, file) && rule.pattern.test(content)) {
          matches.push({
            severity: rule.severity,
            ruleType: rule.type,
            description: rule.description,
            evidence: relative(packagePath, absolutePath),
            file
          });
        }

        if (rule.type === "domain") {
          const matchedDomain = rule.patterns.find((pattern) => content.includes(pattern) || file.includes(pattern));
          if (matchedDomain) {
            matches.push({
              severity: rule.severity,
              ruleType: rule.type,
              description: rule.description,
              evidence: matchedDomain,
              file
            });
          }
        }
      }

      for (const domain of KNOWN_C2_DOMAINS) {
        if (content.includes(domain)) {
          matches.push({
            severity: "CRITICAL",
            ruleType: "domain",
            description: "Known suspicious or C2-related domain referenced in package contents",
            evidence: domain,
            file
          });
        }
      }
    }

    return this.deduplicate(matches);
  }

  private deduplicate(matches: IOCMatch[]): IOCMatch[] {
    const seen = new Set<string>();
    return matches.filter((match) => {
      const key = `${match.ruleType}:${match.description}:${match.evidence}:${match.file ?? ""}`;
      if (seen.has(key)) {
        return false;
      }

      seen.add(key);
      return true;
    });
  }

  private shouldEvaluateContentRule(rule: Extract<IOCRule, { type: "content_regex" }>, file: string): boolean {
    if (rule.description !== "Literal IP address embedded in package source") {
      return true;
    }

    return EXECUTABLE_LIKE_EXTENSIONS.some((extension) => file.endsWith(extension)) || file.endsWith("package.json");
  }
}
