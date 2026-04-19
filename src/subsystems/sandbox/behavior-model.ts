import { KNOWN_C2_DOMAINS } from "../ioc-matcher/c2-domains.js";
import type { SandboxResult, SuspicionFinding, TraceEvent } from "../../core/types.js";

const SENSITIVE_PATH_PATTERNS = [
  { path: "/.ssh/", ruleId: "credential-write-ssh", severity: "CRITICAL", description: "Write to SSH credentials path" },
  { path: "/.aws/", ruleId: "credential-write-aws", severity: "CRITICAL", description: "Write to AWS credentials path" },
  { path: ".npmrc", ruleId: "credential-write-npmrc", severity: "CRITICAL", description: "Write to npm auth configuration" },
  { path: ".github/workflows/", ruleId: "workflow-write", severity: "CRITICAL", description: "Write to GitHub workflow path" }
] as const;

const SENSITIVE_ENV_PREFIXES = ["AWS_", "GITHUB_", "GH_", "NPM_", "NODE_AUTH_", "PYPI_"];

function matchesC2(address: string): boolean {
  return KNOWN_C2_DOMAINS.some((domain) => address.includes(domain));
}

export class BehaviorModel {
  classify(events: TraceEvent[]): Pick<SandboxResult, "suspicious" | "suspicionReasons" | "findings"> {
    const findings: SuspicionFinding[] = [];

    for (const event of events) {
      if (event.type === "network") {
        if (!["127.0.0.1", "::1", "localhost"].includes(event.address)) {
          findings.push({
            ruleId: "outbound-network",
            severity: "HIGH",
            description: "Outbound network connection attempted during install",
            evidence: `${event.address}:${event.port} via ${event.syscall}`
          });
        }

        if (matchesC2(event.address)) {
          findings.push({
            ruleId: "known-c2",
            severity: "CRITICAL",
            description: "Connection to known C2 domain",
            evidence: `${event.address}:${event.port}`
          });
        }
      }

      if (event.type === "file_write") {
        for (const pattern of SENSITIVE_PATH_PATTERNS) {
          if (event.path.includes(pattern.path)) {
            findings.push({
              ruleId: pattern.ruleId,
              severity: pattern.severity,
              description: pattern.description,
              evidence: event.path
            });
          }
        }
      }

      if (event.type === "process_spawn") {
        const joined = [event.command, ...event.args].join(" ");
        if (/(curl|wget).*(\||;).*(bash|sh)/i.test(joined)) {
          findings.push({
            ruleId: "curl-bash",
            severity: "CRITICAL",
            description: "Remote shell execution pattern detected",
            evidence: joined
          });
        } else {
          findings.push({
            ruleId: "spawn-during-install",
            severity: "MEDIUM",
            description: "Process spawned during package installation",
            evidence: joined
          });
        }

        if (/chmod\s+\+x/i.test(joined)) {
          findings.push({
            ruleId: "chmod-exec",
            severity: "MEDIUM",
            description: "Executable permission change during install",
            evidence: joined
          });
        }
      }

      if (event.type === "env_access" && event.variable && SENSITIVE_ENV_PREFIXES.some((prefix) => event.variable?.startsWith(prefix))) {
        findings.push({
          ruleId: "secret-harvest",
          severity: "HIGH",
          description: "Sensitive environment variable accessed during install",
          evidence: event.variable
        });
      }
    }

    const uniqueFindings = this.deduplicate(findings);
    return {
      suspicious: uniqueFindings.length > 0,
      suspicionReasons: uniqueFindings.map((finding) => `${finding.severity}: ${finding.description}`),
      findings: uniqueFindings
    };
  }

  private deduplicate(findings: SuspicionFinding[]): SuspicionFinding[] {
    const seen = new Set<string>();
    return findings.filter((finding) => {
      const key = `${finding.ruleId}:${finding.evidence}`;
      if (seen.has(key)) {
        return false;
      }

      seen.add(key);
      return true;
    });
  }
}
