import { existsSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { basename, extname, join, resolve } from "node:path";
import { tmpdir } from "node:os";

import * as tar from "tar";

import { RegistryClient } from "./registry.js";
import type { PackageEcosystem, PackageManifest, PackageMetadata, PreparedPackage } from "./types.js";

function isLocalPath(spec: string): boolean {
  return spec.startsWith(".") || spec.startsWith("/") || spec.endsWith(".tgz") || spec.endsWith(".tar.gz") || existsSync(resolve(spec));
}

function isDirectoryError(error: unknown): boolean {
  return Boolean(error) && typeof error === "object" && error !== null && "code" in error && (error as { code?: string }).code === "EISDIR";
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await readFile(path);
    return true;
  } catch (error) {
    if (isDirectoryError(error)) {
      return true;
    }

    return false;
  }
}

export class PackageFetcher {
  constructor(private readonly registry = new RegistryClient()) {}

  async preparePackage(packageSpec: string, ecosystem: PackageEcosystem = "npm"): Promise<PreparedPackage> {
    if (isLocalPath(packageSpec)) {
      return this.prepareLocalPackage(resolve(packageSpec));
    }

    return this.prepareRegistryPackage(packageSpec, ecosystem);
  }

  async prepareRegistryPackage(packageSpec: string, ecosystem: PackageEcosystem = "npm"): Promise<PreparedPackage> {
    const metadata = await this.registry.resolve(packageSpec, ecosystem);
    if (!metadata.tarballUrl) {
      throw new Error(`No tarball available for ${packageSpec}`);
    }

    const workspaceDir = await mkdtemp(join(tmpdir(), "husk-registry-"));
    const tarballPath = join(workspaceDir, `${metadata.name.replace(/[\\/]/g, "_")}-${metadata.version}.tgz`);
    const extractDir = join(workspaceDir, "package");
    await mkdir(extractDir, { recursive: true });

    await this.downloadTarball(metadata.tarballUrl, tarballPath);
    await this.extractTarball(tarballPath, extractDir);

    return {
      sourceType: "registry",
      workspaceDir,
      extractDir,
      tarballPath,
      metadata
    };
  }

  async prepareLocalPackage(localPath: string): Promise<PreparedPackage> {
    const workspaceDir = await mkdtemp(join(tmpdir(), "husk-local-"));
    const manifestPath = join(localPath, "package.json");
    const tarballPath = localPath.endsWith(".tgz") || localPath.endsWith(".tar.gz") ? localPath : join(workspaceDir, `${basename(localPath)}.tgz`);
    const extractDir = localPath.endsWith(".tgz") || localPath.endsWith(".tar.gz") ? join(workspaceDir, "package") : localPath;

    if (localPath.endsWith(".tgz") || localPath.endsWith(".tar.gz")) {
      await mkdir(extractDir, { recursive: true });
      await this.extractTarball(localPath, extractDir);
    } else {
      await this.createTarballFromDirectory(localPath, tarballPath);
    }

    const resolvedManifestPath = await fileExists(manifestPath) ? manifestPath : join(extractDir, "package.json");
    const manifest = (JSON.parse(await readFile(resolvedManifestPath, "utf8")) ?? {}) as PackageManifest;
    const metadata: PackageMetadata = {
      ecosystem: "npm",
      name: manifest.name ?? basename(localPath),
      version: manifest.version ?? "0.0.0",
      packageSpec: localPath,
      publishDate: new Date().toISOString(),
      maintainers: [],
      dependencies: manifest.dependencies ?? {},
      installScripts: Object.fromEntries(
        Object.entries(manifest.scripts ?? {}).filter(([name]) => ["preinstall", "install", "postinstall", "prepare"].includes(name))
      ),
      manifest
    };

    return {
      sourceType: localPath.endsWith(".tgz") || localPath.endsWith(".tar.gz") ? "local-tarball" : "local-dir",
      workspaceDir,
      extractDir,
      tarballPath,
      metadata
    };
  }

  async cleanup(prepared: PreparedPackage): Promise<void> {
    if (prepared.sourceType === "local-dir") {
      await rm(prepared.workspaceDir, { recursive: true, force: true });
      return;
    }

    await rm(prepared.workspaceDir, { recursive: true, force: true });
  }

  async extractTarball(tarballPath: string, destination: string): Promise<void> {
    await mkdir(destination, { recursive: true });
    await tar.x({
      file: tarballPath,
      cwd: destination,
      strip: 1,
      gzip: extname(tarballPath).includes("gz")
    });
  }

  async createTarballFromDirectory(sourceDir: string, outputPath: string): Promise<void> {
    await tar.c(
      {
        gzip: true,
        cwd: sourceDir,
        file: outputPath,
        portable: true
      },
      ["."]
    );
  }

  async downloadTarball(url: string, destination: string): Promise<void> {
    const response = await fetch(url, {
      headers: {
        "user-agent": "husk/0.1.0"
      }
    });

    if (!response.ok || !response.body) {
      throw new Error(`Failed to download tarball: ${response.status} ${response.statusText}`);
    }

    const payload = Buffer.from(await response.arrayBuffer());
    const { writeFile } = await import("node:fs/promises");
    await writeFile(destination, payload);
  }

  async readPackageManifest(packageDir: string): Promise<PackageManifest> {
    const manifestPath = join(packageDir, "package.json");
    return JSON.parse(await readFile(manifestPath, "utf8")) as PackageManifest;
  }
}
