import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { glob } from "glob";

import { PackageFetcher } from "../../core/package-fetcher.js";
import { RegistryClient } from "../../core/registry.js";
import type { BehaviorDiff, FileDiff, PackageManifest } from "../../core/types.js";
import { computeAstFingerprint } from "./ast-fingerprint.js";
import { buildInstallScriptDiff, diffCapabilities } from "./capability-diff.js";

async function readManifest(packagePath: string): Promise<PackageManifest> {
  return JSON.parse(await readFile(join(packagePath, "package.json"), "utf8")) as PackageManifest;
}

async function fileHash(path: string): Promise<string> {
  try {
    const content = await readFile(path);
    return createHash("sha256").update(content).digest("hex");
  } catch {
    return "";
  }
}

async function collectFileDiffs(candidatePath: string, previousPath: string): Promise<FileDiff[]> {
  const [candidateFiles, previousFiles] = await Promise.all([
    glob("**/*", { cwd: candidatePath, nodir: true, dot: true, ignore: ["node_modules/**", ".git/**"] }),
    glob("**/*", { cwd: previousPath, nodir: true, dot: true, ignore: ["node_modules/**", ".git/**"] })
  ]);

  const diffs: FileDiff[] = [];
  const fileSet = new Set([...candidateFiles, ...previousFiles]);

  for (const file of fileSet) {
    const inCandidate = candidateFiles.includes(file);
    const inPrevious = previousFiles.includes(file);
    if (inCandidate && !inPrevious) {
      diffs.push({ path: file, changeType: "added" });
      continue;
    }

    if (!inCandidate && inPrevious) {
      diffs.push({ path: file, changeType: "removed" });
      continue;
    }

    const [candidateHash, previousHash] = await Promise.all([fileHash(join(candidatePath, file)), fileHash(join(previousPath, file))]);
    if (candidateHash !== previousHash) {
      diffs.push({ path: file, changeType: "changed" });
    }
  }

  return diffs;
}

export class BehaviorDiffEngine {
  private readonly registry = new RegistryClient();
  private readonly fetcher = new PackageFetcher(this.registry);

  async diff(pkg: string, candidateVersion: string, previousVersion?: string, candidatePath?: string): Promise<BehaviorDiff> {
    const resolvedPreviousVersion = previousVersion ?? (await this.registry.getPreviousVersion(pkg, candidateVersion));
    if (!resolvedPreviousVersion) {
      return {
        packageName: pkg,
        candidateVersion,
        previousVersion: "none",
        newCapabilities: [],
        removedCapabilities: [],
        changedFiles: [],
        installScriptChanged: false,
        suspicionScore: 0
      };
    }

    const previousPrepared = await this.fetcher.preparePackage(`${pkg}@${resolvedPreviousVersion}`);
    const candidatePrepared = candidatePath ? undefined : await this.fetcher.preparePackage(`${pkg}@${candidateVersion}`);
    const currentPath = candidatePath ?? candidatePrepared!.extractDir;

    try {
      const [candidateFingerprint, previousFingerprint, candidateManifest, previousManifest, changedFiles] = await Promise.all([
        computeAstFingerprint(currentPath),
        computeAstFingerprint(previousPrepared.extractDir),
        readManifest(currentPath),
        readManifest(previousPrepared.extractDir),
        collectFileDiffs(currentPath, previousPrepared.extractDir)
      ]);

      const candidateCapabilities = new Set(candidateFingerprint.capabilities);
      Object.keys(candidateManifest.dependencies ?? {}).forEach((dependency) => candidateCapabilities.add(`dependency:${dependency}`));
      const previousCapabilities = new Set(previousFingerprint.capabilities);
      Object.keys(previousManifest.dependencies ?? {}).forEach((dependency) => previousCapabilities.add(`dependency:${dependency}`));

      const { newCapabilities, removedCapabilities } = diffCapabilities(candidateCapabilities, previousCapabilities);
      const candidateScripts = candidateManifest.scripts ?? {};
      const previousScripts = previousManifest.scripts ?? {};
      const installScriptDiff = buildInstallScriptDiff(previousScripts, candidateScripts);
      const installScriptChanged = Boolean(installScriptDiff);
      const suspicionScore = Math.min(100, newCapabilities.length * 8 + changedFiles.length * 2 + (installScriptChanged ? 10 : 0));

      return {
        packageName: pkg,
        candidateVersion,
        previousVersion: resolvedPreviousVersion,
        newCapabilities,
        removedCapabilities,
        changedFiles,
        installScriptChanged,
        installScriptDiff,
        suspicionScore
      };
    } finally {
      await this.fetcher.cleanup(previousPrepared).catch(() => undefined);
      if (candidatePrepared) {
        await this.fetcher.cleanup(candidatePrepared).catch(() => undefined);
      }
    }
  }
}
