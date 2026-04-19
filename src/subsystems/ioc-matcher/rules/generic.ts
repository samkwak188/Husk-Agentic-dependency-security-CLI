import type { IOCRule } from "../../../core/types.js";

export const GENERIC_IOCS: IOCRule[] = [
  {
    type: "content_regex",
    pattern: /eval\s*\(\s*require\s*\(\s*["']child_process["']\s*\)/i,
    severity: "CRITICAL",
    description: "Eval combined with child_process usage"
  },
  {
    type: "content_regex",
    pattern: /Buffer\.from\([^)]*base64[^)]*\).*eval/i,
    severity: "HIGH",
    description: "Base64 decode followed by eval"
  },
  {
    // Lowered to LOW: legitimate packages routinely contain IP literals
    // (network parsers, validators, examples, mock data). On its own this
    // is too noisy to drive a SUSPICIOUS verdict. It still contributes to
    // the cumulative score when other signals fire — that's the right
    // weight for "weakly correlates with malicious behavior".
    type: "content_regex",
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
    severity: "LOW",
    description: "Literal IP address embedded in package source"
  },
  {
    type: "content_regex",
    pattern: /require\(['"]dns['"]\)\.resolve|dns\.resolve/i,
    severity: "HIGH",
    description: "DNS resolution during install path"
  },
  {
    // SSH credentials are almost never legitimately referenced in npm/PyPI
    // package source. Mention alone is enough — tightened context unnecessary.
    type: "content_regex",
    pattern: /\b(authorized_keys|id_rsa|id_dsa|id_ed25519|id_ecdsa)\b/,
    severity: "HIGH",
    description: "SSH key file reference"
  },
  {
    // Package-manager credentials are MUCH more commonly mentioned in legit
    // tooling (publish workflows, init scripts, docs in code comments).
    // Require the path to appear within a read-side or network context to
    // distinguish "tool that mentions .npmrc" from "tool that exfiltrates it".
    // Eliminates @angular/cli's package-metadata.js FP while still catching
    // the actual exfil patterns the dataset uses.
    type: "content_regex",
    pattern: /(readFile(?:Sync)?|createReadStream|fs\.read[A-Za-z]*|fetch|axios|got\.|request\(|http\.(?:get|post|request)|XMLHttpRequest|webhook|exfil|telegram|discord)[^;\n]{0,200}\.(npmrc|pypirc|aws\/credentials)/i,
    severity: "HIGH",
    description: "Credential file path used by a read or network sink"
  },
  {
    type: "content_regex",
    pattern: /require\(['"]\\x63\\x68\\x69\\x6c\\x64/i,
    severity: "HIGH",
    description: "Obfuscated require call targeting child_process"
  },
  {
    type: "script_pattern",
    pattern: /(curl|wget).*(\||;).*(bash|sh)/i,
    severity: "CRITICAL",
    description: "Remote shell pattern in lifecycle script"
  }
];
