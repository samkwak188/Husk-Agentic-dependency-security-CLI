import { mkdtemp, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";

import { glob } from "glob";

import type { GroundTruthEntry } from "../src/core/types.js";

function parseDateAndVersionFromZip(zipPath: string): { discoveryDate: string; version: string } {
  const name = basename(zipPath, ".zip");
  const match = name.match(/(?<date>\d{4}-\d{2}-\d{2}).*?-v(?<version>[^-]+)$/);
  return {
    discoveryDate: match?.groups?.date ?? new Date().toISOString().slice(0, 10),
    version: match?.groups?.version ?? "0.0.0"
  };
}

function normalizePackageName(input: string): string {
  return input.replace(/\.zip$/, "").replace(/^\d{4}-\d{2}-\d{2}-/, "").replace(/-v[^-]+$/, "");
}

async function loadDataDogEntries(root: string): Promise<GroundTruthEntry[]> {
  const manifestPaths = await glob("samples/{npm,pypi}/**/manifest.json", {
    cwd: root,
    absolute: true
  });

  const zipFiles = await glob("**/*.zip", {
    cwd: root,
    absolute: true
  });
  const zipLookup = new Map(zipFiles.map((zip) => [basename(zip), zip]));
  const entries: GroundTruthEntry[] = [];

  for (const manifestPath of manifestPaths) {
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Record<string, null | string[]>;
    const ecosystem = manifestPath.includes("/npm/") ? "npm" : "pypi";

    for (const [name, versions] of Object.entries(manifest)) {
      if (versions === null) {
        const candidateZip = zipFiles.find((zip) => normalizePackageName(basename(zip)) === name);
        if (!candidateZip) {
          continue;
        }

        const parsed = parseDateAndVersionFromZip(candidateZip);
        entries.push({
          name,
          version: parsed.version,
          ecosystem,
          label: "malicious",
          source: "datadog",
          category: "malicious_intent",
          zipPath: candidateZip,
          discoveryDate: parsed.discoveryDate
        });
        continue;
      }

      for (const version of versions) {
        const zipName = zipFiles.find((zip) => basename(zip).includes(`${name.replace("/", "-")}-v${version}`)) ?? zipLookup.get(`${name}-v${version}.zip`);
        if (!zipName) {
          continue;
        }

        const parsed = parseDateAndVersionFromZip(zipName);
        entries.push({
          name,
          version,
          ecosystem,
          label: "malicious",
          source: "datadog",
          category: "compromised",
          zipPath: zipName,
          discoveryDate: parsed.discoveryDate
        });
      }
    }
  }

  return entries;
}

function extractField(text: string, key: string): string | undefined {
  const match = text.match(new RegExp(`^${key}:\\s*(.+)$`, "im"));
  return match?.[1]?.trim();
}

async function loadBackstabbersEntries(root: string): Promise<GroundTruthEntry[]> {
  const metadataFiles = await glob("**/*.{json,yml,yaml,md}", {
    cwd: root,
    absolute: true
  });
  const zipFiles = await glob("**/*.zip", {
    cwd: root,
    absolute: true
  });
  const entries: GroundTruthEntry[] = [];

  for (const file of metadataFiles) {
    const text = await readFile(file, "utf8").catch(() => "");
    const name = extractField(text, "name") ?? extractField(text, "package") ?? normalizePackageName(basename(file));
    const version = extractField(text, "version") ?? "0.0.0";
    const ecosystem = /pypi/i.test(text) ? "pypi" : "npm";
    const zipPath = zipFiles.find((zip) => basename(zip).includes(name) || basename(zip).includes(version));
    if (!zipPath) {
      continue;
    }

    entries.push({
      name,
      version,
      ecosystem,
      label: "malicious",
      source: "backstabbers",
      category: /compromised/i.test(text) ? "compromised" : "malicious_intent",
      zipPath,
      discoveryDate: parseDateAndVersionFromZip(zipPath).discoveryDate
    });
  }

  return entries;
}

export async function loadGroundTruth(): Promise<GroundTruthEntry[]> {
  const datadogRoot = resolve("datasets/datadog");
  const backstabbersRoot = resolve("datasets/backstabbers");
  const [datadog, backstabbers] = await Promise.all([
    loadDataDogEntries(datadogRoot).catch(() => []),
    loadBackstabbersEntries(backstabbersRoot).catch(() => [])
  ]);

  return [...datadog, ...backstabbers].sort((left, right) => left.name.localeCompare(right.name) || left.version.localeCompare(right.version));
}

export async function extractGroundTruthZip(zipPath: string): Promise<string> {
  const outputDir = await mkdtemp(join(tmpdir(), "husk-dataset-"));
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn("unzip", ["-P", "infected", "-q", zipPath, "-d", outputDir], {
      stdio: "ignore"
    });
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise();
        return;
      }

      reject(new Error(`Failed to extract ${zipPath}`));
    });
  });

  const packageJsons = await glob("**/package.json", {
    cwd: outputDir,
    absolute: true
  });
  if (!packageJsons.length) {
    return outputDir;
  }

  return resolve(packageJsons[0], "..");
}
