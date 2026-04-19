import { spawn } from "node:child_process";
import { createInterface } from "node:readline/promises";
import process from "node:process";

import { HuskOrchestrator } from "../agents/orchestrator.js";
import type { HuskVerdict, PackageEcosystem, PolicyAction, ScanEvent } from "../core/types.js";

export type InstallManager = "npm" | "pip";

export interface GuardedInstallPlan {
  manager: InstallManager;
  ecosystem: PackageEcosystem;
  packageSpecs: string[];
  overallAction: PolicyAction;
  installCommand: {
    command: string;
    args: string[];
    display: string;
  };
  verdicts: HuskVerdict[];
  blocked: HuskVerdict[];
  warnings: HuskVerdict[];
}

export interface GuardedInstallOptions {
  sandbox?: boolean;
  staticOnly?: boolean;
  yes?: boolean;
  force?: boolean;
  dryRun?: boolean;
}

function resolveEcosystem(manager: InstallManager): PackageEcosystem {
  return manager === "pip" ? "pypi" : "npm";
}

export function buildInstallCommand(manager: InstallManager, packageSpecs: string[]): GuardedInstallPlan["installCommand"] {
  if (manager === "pip") {
    const command = process.env.HUSK_PIP_COMMAND?.trim() || "python3";
    const args =
      command === "python3" || command === "python"
        ? ["-m", "pip", "install", ...packageSpecs]
        : ["install", ...packageSpecs];
    return {
      command,
      args,
      display: [command, ...args].join(" ")
    };
  }

  return {
    command: "npm",
    args: ["install", ...packageSpecs],
    display: ["npm", "install", ...packageSpecs].join(" ")
  };
}

export async function planGuardedInstall(
  manager: InstallManager,
  packageSpecs: string[],
  options: Pick<GuardedInstallOptions, "sandbox" | "staticOnly"> & { onPackageStart?: (spec: string) => ((event: ScanEvent) => void) | undefined; onPackageEnd?: (spec: string) => void }
): Promise<GuardedInstallPlan> {
  const orchestrator = new HuskOrchestrator();
  const ecosystem = resolveEcosystem(manager);
  const verdicts: HuskVerdict[] = [];

  for (const packageSpec of packageSpecs) {
    const emitEvent = options.onPackageStart?.(packageSpec);
    try {
      const verdict = await orchestrator.analyze(packageSpec, {
        ecosystem,
        forceSandbox: manager === "npm" ? options.sandbox : false,
        staticOnly: manager === "pip" ? true : options.staticOnly,
        disableSandbox: manager !== "npm",
        emitEvent
      });
      verdicts.push(verdict);
    } finally {
      options.onPackageEnd?.(packageSpec);
    }
  }

  const blocked = verdicts.filter((verdict) => verdict.policy.action === "BLOCK");
  const warnings = verdicts.filter((verdict) => verdict.policy.action === "WARN");
  const overallAction = blocked.length ? "BLOCK" : warnings.length ? "WARN" : "ALLOW";

  return {
    manager,
    ecosystem,
    packageSpecs,
    overallAction,
    installCommand: buildInstallCommand(manager, packageSpecs),
    verdicts,
    blocked,
    warnings
  };
}

async function confirmWarningProceed(plan: GuardedInstallPlan): Promise<boolean> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return false;
  }

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    const count = plan.warnings.length;
    const names = plan.warnings.map((verdict) => `${verdict.packageName}@${verdict.packageVersion}`).join(", ");
    const answer = await rl.question(
      `\n  Husk flagged ${count} package${count === 1 ? "" : "s"} as WARN: ${names}\n  Proceed with \`${plan.installCommand.display}\`? [y/N] `
    );
    return ["y", "yes"].includes(answer.trim().toLowerCase());
  } finally {
    rl.close();
  }
}

export async function executeGuardedInstall(plan: GuardedInstallPlan, options: GuardedInstallOptions): Promise<number> {
  if (plan.overallAction === "BLOCK" && !options.force) {
    return 40;
  }

  if (plan.overallAction === "WARN" && !options.yes && !options.force) {
    const confirmed = await confirmWarningProceed(plan);
    if (!confirmed) {
      return 20;
    }
  }

  if (options.dryRun) {
    return 0;
  }

  return new Promise<number>((resolve) => {
    const child = spawn(plan.installCommand.command, plan.installCommand.args, {
      stdio: "inherit"
    });

    child.on("error", () => resolve(1));
    child.on("exit", (code) => resolve(code ?? 1));
  });
}
