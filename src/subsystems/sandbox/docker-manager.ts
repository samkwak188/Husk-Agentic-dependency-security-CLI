import { access, copyFile, mkdir, readFile, rm } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { join } from "node:path";

import Docker from "dockerode";

import { PackageFetcher } from "../../core/package-fetcher.js";
import type { SandboxResult } from "../../core/types.js";
import { BehaviorModel } from "./behavior-model.js";
import { loadSeccompProfile } from "./seccomp.js";
import { StraceParser } from "./strace-parser.js";

interface AnalyzeOptions {
  allowNetwork?: boolean;
  timeout?: number;
}

export async function isSandboxReady(): Promise<boolean> {
  try {
    await access("/var/run/docker.sock", fsConstants.R_OK | fsConstants.W_OK);
    await new Docker().getImage("husk-sandbox").inspect();
    return true;
  } catch {
    return false;
  }
}

export class SandboxManager {
  private readonly docker: Docker;
  private readonly packageFetcher: PackageFetcher;
  private readonly parser: StraceParser;
  private readonly behaviorModel: BehaviorModel;

  constructor() {
    this.docker = new Docker();
    this.packageFetcher = new PackageFetcher();
    this.parser = new StraceParser();
    this.behaviorModel = new BehaviorModel();
  }

  async analyze(packageSpec: string, options: AnalyzeOptions = {}): Promise<SandboxResult> {
    const timeout = options.timeout ?? 60_000;
    await this.assertDockerAvailable();
    await this.assertSandboxImageAvailable();

    const prepared = await this.packageFetcher.preparePackage(packageSpec);
    const sandboxDir = join(prepared.workspaceDir, "sandbox");
    const mountedTarballPath = join(sandboxDir, "pkg.tgz");
    await mkdir(sandboxDir, { recursive: true });
    await copyFile(prepared.tarballPath, mountedTarballPath);

    const startedAt = Date.now();
    const seccompProfile = (await loadSeccompProfile()).replace(/\s+/g, "");
    const container = await this.docker.createContainer({
      Image: "husk-sandbox",
      Cmd: ["file:///sandbox/pkg.tgz"],
      Tty: false,
      WorkingDir: "/sandbox",
      HostConfig: {
        AutoRemove: false,
        Binds: [`${sandboxDir}:/sandbox`],
        CapDrop: ["ALL"],
        Memory: 512 * 1024 * 1024,
        NanoCpus: 1_000_000_000,
        NetworkMode: options.allowNetwork ? "bridge" : "none",
        ReadonlyRootfs: false,
        SecurityOpt: [`seccomp=${seccompProfile}`]
      }
    });

    try {
      await container.start();
      const status = await this.waitForContainer(container, timeout);
      const rawTrace = await this.readMaybe(join(sandboxDir, "trace.log"));
      const installLog = await this.readMaybe(join(sandboxDir, "install.log"));
      const events = this.parser.parse(rawTrace);
      const summary = this.parser.summarize(events);
      const behavior = this.behaviorModel.classify(events);

      return {
        exitCode: status,
        traceEvents: events,
        installLog,
        duration: Date.now() - startedAt,
        networkAttempts: summary.networkAttempts,
        fileWrites: summary.fileWrites,
        processSpawns: summary.processSpawns,
        envAccesses: summary.envAccesses,
        suspicious: behavior.suspicious,
        suspicionReasons: behavior.suspicionReasons,
        findings: behavior.findings,
        rawTrace
      };
    } finally {
      await container.remove({ force: true }).catch(() => undefined);
      await rm(sandboxDir, { recursive: true, force: true }).catch(() => undefined);
      await this.packageFetcher.cleanup(prepared).catch(() => undefined);
    }
  }

  private async waitForContainer(container: Docker.Container, timeout: number): Promise<number> {
    let timer: NodeJS.Timeout | undefined;
    const waitPromise = container.wait().then((result) => result.StatusCode ?? 0);
    const timeoutPromise = new Promise<number>((_, reject) => {
      timer = setTimeout(async () => {
        await container.kill().catch(() => undefined);
        reject(new Error(`Sandbox analysis timed out after ${timeout}ms`));
      }, timeout);
    });

    try {
      return await Promise.race([waitPromise, timeoutPromise]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async assertDockerAvailable(): Promise<void> {
    await access("/var/run/docker.sock", fsConstants.R_OK | fsConstants.W_OK).catch(() => {
      throw new Error("Docker socket is unavailable. Install and start Docker Desktop to run sandbox analysis.");
    });
  }

  private async assertSandboxImageAvailable(): Promise<void> {
    await this.docker
      .getImage("husk-sandbox")
      .inspect()
      .catch(() => {
        throw new Error("Sandbox image 'husk-sandbox' is missing. Run 'npm run setup' or build docker/Dockerfile.sandbox first.");
      });
  }

  private async readMaybe(path: string): Promise<string> {
    try {
      return await readFile(path, "utf8");
    } catch {
      return "";
    }
  }
}
