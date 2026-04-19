import { describe, expect, it } from "vitest";

import { buildInstallCommand } from "../src/cli/guarded-install.js";

describe("buildInstallCommand", () => {
  it("builds npm install commands", () => {
    const command = buildInstallCommand("npm", ["lodash@4.17.21"]);

    expect(command.command).toBe("npm");
    expect(command.args).toEqual(["install", "lodash@4.17.21"]);
  });

  it("builds pip install commands through python3 by default", () => {
    const command = buildInstallCommand("pip", ["requests==2.32.0"]);

    expect(command.command).toBe("python3");
    expect(command.args).toEqual(["-m", "pip", "install", "requests==2.32.0"]);
  });
});
