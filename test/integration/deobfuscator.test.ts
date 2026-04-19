import { describe, expect, it } from "vitest";

import { DeobfuscationPipeline } from "../../src/subsystems/deobfuscator/pipeline.js";

describe("DeobfuscationPipeline", () => {
  it("reveals base64-wrapped eval payloads", async () => {
    const pipeline = new DeobfuscationPipeline();
    const source = 'eval(Buffer.from("Y29uc29sZS5sb2coImV2aWwiKQ==", "base64").toString())';
    const result = await pipeline.deobfuscate(source);
    expect(result.deobfuscatedSource).toContain('console.log("evil")');
    expect(result.suspicionScore).toBeGreaterThanOrEqual(0);
  });
});
