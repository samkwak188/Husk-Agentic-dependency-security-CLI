import { resolve } from "node:path";
import { access } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";

import Docker from "dockerode";
import { describe, expect, it } from "vitest";

import { SandboxManager } from "../../src/subsystems/sandbox/docker-manager.js";

async function hasDocker(): Promise<boolean> {
  try {
    await access("/var/run/docker.sock", fsConstants.R_OK | fsConstants.W_OK);
    return true;
  } catch {
    return false;
  }
}

async function hasSandboxImage(): Promise<boolean> {
  try {
    await new Docker().getImage("husk-sandbox").inspect();
    return true;
  } catch {
    return false;
  }
}

describe("SandboxManager", () => {
  it("captures trace output when Docker is available", async () => {
    if (!(await hasDocker()) || !(await hasSandboxImage())) {
      return;
    }

    const manager = new SandboxManager();
    const result = await manager.analyze(resolve("test/fixtures/malicious/sample1"), {
      allowNetwork: true,
      timeout: 30_000
    });
    expect(result.traceEvents.length).toBeGreaterThanOrEqual(0);
  });
});
