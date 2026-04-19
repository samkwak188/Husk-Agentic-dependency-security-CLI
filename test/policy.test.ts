import { describe, expect, it } from "vitest";

import { PolicyEngine } from "../src/core/policy.js";
import type { HuskVerdict } from "../src/core/types.js";

function makeVerdict(overrides: Partial<HuskVerdict> = {}): HuskVerdict {
  return {
    ecosystem: "npm",
    verdict: "CLEAN",
    confidence: 0.3,
    reasons: [],
    recommendations: [],
    policy: {
      action: "ALLOW",
      summary: "",
      reasons: [],
      policyName: "",
      canOverride: false,
      reviewRequired: false
    },
    iocs: [],
    workflow: {
      provider: "deterministic",
      apiEnabled: false,
      triage: { mode: "deterministic" },
      dynamicNarration: { mode: "deterministic" },
      reporting: { mode: "deterministic" }
    },
    scanDuration: 1,
    timestamp: new Date().toISOString(),
    packageName: "safe-package",
    packageVersion: "1.0.0",
    ...overrides
  };
}

describe("PolicyEngine", () => {
  it("blocks critical malware signals by default", async () => {
    const engine = new PolicyEngine();
    const decision = await engine.evaluate(
      makeVerdict({
        verdict: "MALICIOUS",
        iocs: [
          {
            severity: "CRITICAL",
            ruleType: "domain",
            description: "Known malicious webhook",
            evidence: "discord.com/api/webhooks"
          }
        ]
      })
    );

    expect(decision.action).toBe("BLOCK");
    expect(decision.reasons.some((reason) => reason.includes("Critical indicators"))).toBe(true);
  });

  it("allows clean packages through default policy", async () => {
    const engine = new PolicyEngine();
    const decision = await engine.evaluate(makeVerdict());

    expect(decision.action).toBe("ALLOW");
    expect(decision.reviewRequired).toBe(false);
  });
});
