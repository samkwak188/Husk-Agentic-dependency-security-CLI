import type { Capability } from "../../core/types.js";

function mapCapability(value: string): Capability {
  if (value.startsWith("module:http") || value.startsWith("call:http") || value.startsWith("call:https") || value.startsWith("module:net")) {
    return { type: "network", detail: value };
  }

  if (value.startsWith("module:fs") || value.startsWith("call:fs")) {
    return { type: "filesystem", detail: value };
  }

  if (value.startsWith("module:child_process") || value.startsWith("call:child_process")) {
    return { type: "process", detail: value };
  }

  if (value.startsWith("env:")) {
    return { type: "env", detail: value };
  }

  if (value.startsWith("dependency:")) {
    return { type: "dependency", detail: value };
  }

  return { type: "script", detail: value };
}

export function diffCapabilities(candidate: Set<string>, previous: Set<string>): {
  newCapabilities: Capability[];
  removedCapabilities: Capability[];
} {
  const newCapabilities = [...candidate].filter((value) => !previous.has(value)).map(mapCapability);
  const removedCapabilities = [...previous].filter((value) => !candidate.has(value)).map(mapCapability);
  return {
    newCapabilities,
    removedCapabilities
  };
}

export function buildInstallScriptDiff(previousScripts: Record<string, string>, candidateScripts: Record<string, string>): string | undefined {
  const keys = [...new Set([...Object.keys(previousScripts), ...Object.keys(candidateScripts)])].sort();
  const lines: string[] = [];

  for (const key of keys) {
    const before = previousScripts[key];
    const after = candidateScripts[key];
    if (before === after) {
      continue;
    }

    if (before !== undefined) {
      lines.push(`- ${key}: ${before}`);
    }

    if (after !== undefined) {
      lines.push(`+ ${key}: ${after}`);
    }
  }

  return lines.length ? lines.join("\n") : undefined;
}
