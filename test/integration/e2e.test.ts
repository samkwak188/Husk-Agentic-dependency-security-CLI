import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { HuskOrchestrator } from "../../src/agents/orchestrator.js";

describe("HuskOrchestrator", () => {
  it("flags a malicious local fixture", async () => {
    const orchestrator = new HuskOrchestrator();
    const fixture = resolve("test/fixtures/malicious/sample1");
    const verdict = await orchestrator.analyze(fixture, {
      localPath: fixture,
      staticOnly: true
    });
    expect(["MALICIOUS", "SUSPICIOUS"]).toContain(verdict.verdict);
    expect(verdict.iocs.length).toBeGreaterThan(0);
    expect(verdict.policy.action).toBe("BLOCK");
  });

  it("keeps a benign local fixture clean", async () => {
    const orchestrator = new HuskOrchestrator();
    const fixture = resolve("test/fixtures/benign/sample1");
    const verdict = await orchestrator.analyze(fixture, {
      localPath: fixture,
      staticOnly: true
    });
    expect(verdict.verdict).toBe("CLEAN");
    expect(verdict.policy.action).toBe("ALLOW");
  });
});
