import type { IOCRule } from "../../../core/types.js";

export const SHAI_HULUD_IOCS: IOCRule[] = [
  {
    type: "filename",
    pattern: "bun_environment.js",
    severity: "CRITICAL",
    description: "Shai-Hulud Stage 1 loader"
  },
  {
    type: "filename",
    pattern: "setup_bun.js",
    severity: "CRITICAL",
    description: "Shai-Hulud installer"
  },
  {
    type: "filename",
    pattern: "shai-hulud-workflow.yml",
    severity: "CRITICAL",
    description: "Shai-Hulud GitHub Actions worm artifact"
  },
  {
    type: "content_regex",
    pattern: /Sha1-Hulud|Shai-Hulud|shai\.hulud/i,
    severity: "CRITICAL",
    description: "Shai-Hulud family marker in package contents"
  },
  {
    // Tightened on TWO axes vs the original:
    //   - Requires a write-side context (writeFile / mkdir / append) within
    //     ~200 chars, not just a path mention.
    //   - Severity downgraded HIGH → MEDIUM. Legit CI scaffolders and
    //     workflow generators (e.g. playwright's lib/agents/generateAgents)
    //     legitimately write to .github/workflows. As a CO-SIGNAL this is
    //     valuable; on its own it's not enough to flag a SUSPICIOUS verdict.
    //     Husk's correlation rule promotes MEDIUM+another to SUSPICIOUS,
    //     which is the right severity for this pattern.
    type: "content_regex",
    pattern: /(writeFile(?:Sync)?|appendFile(?:Sync)?|copyFile(?:Sync)?|fs\.create|mkdir(?:Sync)?|fs\.outputFile)[^;\n]{0,200}\.github\/workflows\/[^"'\s)]*\.ya?ml/i,
    severity: "MEDIUM",
    description: "Writes to .github/workflows (worm-propagation pattern)"
  },
  {
    type: "script_pattern",
    pattern: /preinstall.*bun|bun.*preinstall/i,
    severity: "HIGH",
    description: "Bun preload during install lifecycle"
  },
  {
    type: "package_version",
    name: "@ctrl/tinycolor",
    versions: ["4.1.2"],
    severity: "CRITICAL",
    description: "Known compromised version associated with Shai-Hulud reporting"
  },
  {
    type: "domain",
    patterns: ["shai-hulud", "discord.com/api/webhooks", "transfer.sh"],
    severity: "CRITICAL",
    description: "Known Shai-Hulud infrastructure marker"
  },
  {
    type: "content_regex",
    pattern: /process\.env\.(GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY|AWS_SECRET)/i,
    severity: "HIGH",
    description: "Environment-variable exfiltration pattern"
  }
];
