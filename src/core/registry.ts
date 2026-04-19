import semver from "semver";

import type { PackageEcosystem, PackageManifest, PackageMetadata } from "./types.js";

interface NpmRegistryDocument {
  "dist-tags"?: Record<string, string>;
  versions?: Record<
    string,
    PackageManifest & {
      dist?: {
        tarball?: string;
      };
      maintainers?: Array<string | { name?: string; email?: string }>;
      time?: string;
    }
  >;
  time?: Record<string, string> & {
    unpublished?: { time?: string; name?: string; versions?: string[] };
  };
}

export type RegistryErrorCode =
  | "unknown-package"           // Registry has no such package at all (404)
  | "unpublished-package"       // Package was fully unpublished from the registry
  | "security-placeholder"      // npm replaced the package with a *-security stub
  | "unpublished-version"       // The exact version was removed (likely malicious)
  | "unknown-version"           // The version was never published
  | "no-default-version"        // No `latest` tag and caller didn't pin a version
  | "fetch-failed";             // Network / HTTP error talking to the registry

export interface RegistryErrorDetails {
  code: RegistryErrorCode;
  packageName: string;
  ecosystem: PackageEcosystem;
  requestedVersion?: string;
  latest?: string;
  availableVersions?: string[];
  publishedAt?: string;
  unpublishedAt?: string;
  cause?: string;
}

/**
 * Structured error so the CLI can render a precise, security-aware message
 * instead of a generic "not found". An unpublished version is, for Husk's
 * purposes, *itself* an indicator that the package was malicious enough that
 * npm took action.
 */
export class RegistryError extends Error {
  readonly code: RegistryErrorCode;
  readonly packageName: string;
  readonly ecosystem: PackageEcosystem;
  readonly requestedVersion?: string;
  readonly latest?: string;
  readonly availableVersions?: string[];
  readonly publishedAt?: string;
  readonly unpublishedAt?: string;

  constructor(details: RegistryErrorDetails) {
    super(buildRegistryErrorMessage(details));
    this.name = "RegistryError";
    this.code = details.code;
    this.packageName = details.packageName;
    this.ecosystem = details.ecosystem;
    this.requestedVersion = details.requestedVersion;
    this.latest = details.latest;
    this.availableVersions = details.availableVersions;
    this.publishedAt = details.publishedAt;
    this.unpublishedAt = details.unpublishedAt;
  }
}

function buildRegistryErrorMessage(details: RegistryErrorDetails): string {
  const target = details.requestedVersion ? `${details.packageName}@${details.requestedVersion}` : details.packageName;
  switch (details.code) {
    case "unknown-package":
      return `${details.packageName} does not exist in the ${details.ecosystem} registry`;
    case "unpublished-package":
      return `${details.packageName} was unpublished from the ${details.ecosystem} registry${details.unpublishedAt ? ` on ${details.unpublishedAt}` : ""}`;
    case "security-placeholder":
      return `${details.packageName} was replaced by a security advisory placeholder (latest = ${details.latest})`;
    case "unpublished-version":
      return `${target} was unpublished from the ${details.ecosystem} registry — this is the registry's response to confirmed malicious or harmful versions`;
    case "unknown-version":
      return `${target} was never published to the ${details.ecosystem} registry`;
    case "no-default-version":
      return `Unable to resolve a default version for ${details.packageName}`;
    case "fetch-failed":
    default:
      return `Failed to fetch ${target} from the ${details.ecosystem} registry${details.cause ? `: ${details.cause}` : ""}`;
  }
}

function isSecurityPlaceholderTag(tag: string | undefined): boolean {
  return Boolean(tag && /-security$/.test(tag));
}

interface PyPiDocument {
  info?: {
    name?: string;
    version?: string;
    author?: string;
    maintainer?: string;
  };
  releases?: Record<
    string,
    Array<{
      upload_time_iso_8601?: string;
      url?: string;
    }>
  >;
}

export interface ParsedPackageSpec {
  name: string;
  version?: string;
  packageSpec: string;
  ecosystem: PackageEcosystem;
}

export function parsePackageSpec(packageSpec: string, ecosystem: PackageEcosystem = "npm"): ParsedPackageSpec {
  if (ecosystem === "pypi") {
    const pypiMatch = packageSpec.match(/^(?<name>[^=<>!~]+?)(==(?<version>.+))?$/);
    if (!pypiMatch?.groups?.name) {
      throw new Error(`Invalid PyPI package spec: ${packageSpec}`);
    }

    return {
      ecosystem,
      name: pypiMatch.groups.name.trim(),
      version: pypiMatch.groups.version?.trim(),
      packageSpec
    };
  }

  if (packageSpec.startsWith("@")) {
    const atIndex = packageSpec.lastIndexOf("@");
    const slashIndex = packageSpec.indexOf("/");
    if (atIndex > slashIndex) {
      return {
        ecosystem,
        name: packageSpec.slice(0, atIndex),
        version: packageSpec.slice(atIndex + 1),
        packageSpec
      };
    }

    return {
      ecosystem,
      name: packageSpec,
      packageSpec
    };
  }

  const [name, version] = packageSpec.split("@");
  return {
    ecosystem,
    name,
    version,
    packageSpec
  };
}

async function fetchJson<T>(url: string): Promise<{ ok: true; data: T } | { ok: false; status: number; statusText: string }> {
  const response = await fetch(url, {
    headers: {
      "user-agent": "husk/0.1.0"
    }
  });

  if (!response.ok) {
    return { ok: false, status: response.status, statusText: response.statusText };
  }

  return { ok: true, data: (await response.json()) as T };
}

function normalizeMaintainers(input: Array<string | { name?: string; email?: string }> | undefined): string[] {
  if (!input) {
    return [];
  }

  return input
    .map((entry) => {
      if (typeof entry === "string") {
        return entry;
      }

      return [entry.name, entry.email].filter(Boolean).join(" ");
    })
    .filter(Boolean);
}

export class RegistryClient {
  async resolve(packageSpec: string, ecosystem: PackageEcosystem = "npm"): Promise<PackageMetadata> {
    const parsed = parsePackageSpec(packageSpec, ecosystem);
    return ecosystem === "npm" ? this.resolveNpm(parsed.name, parsed.version, parsed.packageSpec) : this.resolvePyPi(parsed.name, parsed.version, parsed.packageSpec);
  }

  async resolveNpm(name: string, requestedVersion?: string, packageSpec = name): Promise<PackageMetadata> {
    const encoded = name.startsWith("@") ? name.replace("/", "%2f") : encodeURIComponent(name);
    const result = await fetchJson<NpmRegistryDocument>(`https://registry.npmjs.org/${encoded}`);

    if (!result.ok) {
      if (result.status === 404) {
        throw new RegistryError({
          code: "unknown-package",
          packageName: name,
          ecosystem: "npm",
          requestedVersion
        });
      }
      throw new RegistryError({
        code: "fetch-failed",
        packageName: name,
        ecosystem: "npm",
        requestedVersion,
        cause: `${result.status} ${result.statusText}`
      });
    }

    const document = result.data;
    const distTags = document["dist-tags"] ?? {};
    const time = document.time ?? {};
    const versions = document.versions ?? {};
    const availableVersions = Object.keys(versions).filter((candidate) => semver.valid(candidate)).sort(semver.compare);
    const latest = distTags.latest;

    // Whole-package unpublishment leaves a `time.unpublished` block and
    // (usually) no `versions` at all.
    if (time.unpublished) {
      throw new RegistryError({
        code: "unpublished-package",
        packageName: name,
        ecosystem: "npm",
        requestedVersion,
        unpublishedAt: time.unpublished.time,
        availableVersions,
        latest
      });
    }

    // npm replaces taken-down packages with a `0.0.1-security` (or similar
    // `*-security`) placeholder and points `latest` at it.
    if (isSecurityPlaceholderTag(latest) && availableVersions.length <= 1) {
      throw new RegistryError({
        code: "security-placeholder",
        packageName: name,
        ecosystem: "npm",
        requestedVersion,
        latest,
        availableVersions
      });
    }

    // Resolve `latest` if no version was pinned.
    const version = requestedVersion === "latest" ? latest : (requestedVersion ?? latest);
    if (!version) {
      throw new RegistryError({
        code: "no-default-version",
        packageName: name,
        ecosystem: "npm",
        requestedVersion,
        availableVersions
      });
    }

    const versionDoc = versions[version];
    if (!versionDoc) {
      // Distinguish "was published but later removed" from "never existed".
      const wasOncePublished = Boolean(time[version]);
      throw new RegistryError({
        code: wasOncePublished ? "unpublished-version" : "unknown-version",
        packageName: name,
        ecosystem: "npm",
        requestedVersion: version,
        publishedAt: time[version],
        latest,
        availableVersions
      });
    }

    return {
      ecosystem: "npm",
      name,
      version,
      packageSpec,
      tarballUrl: versionDoc.dist?.tarball,
      publishDate: document.time?.[version] ?? versionDoc.time,
      previousVersion: this.getPreviousVersionFromDocument(version, document),
      distTags,
      maintainers: normalizeMaintainers(versionDoc.maintainers),
      dependencies: versionDoc.dependencies ?? {},
      installScripts: this.pickInstallScripts(versionDoc.scripts),
      manifest: versionDoc,
      raw: document as Record<string, unknown>
    };
  }

  async resolvePyPi(name: string, requestedVersion?: string, packageSpec = name): Promise<PackageMetadata> {
    const result = await fetchJson<PyPiDocument>(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    if (!result.ok) {
      if (result.status === 404) {
        throw new RegistryError({
          code: "unknown-package",
          packageName: name,
          ecosystem: "pypi",
          requestedVersion
        });
      }
      throw new RegistryError({
        code: "fetch-failed",
        packageName: name,
        ecosystem: "pypi",
        requestedVersion,
        cause: `${result.status} ${result.statusText}`
      });
    }
    const document = result.data;
    const availableVersions = Object.keys(document.releases ?? {});
    const version = requestedVersion ?? document.info?.version;
    if (!version) {
      throw new RegistryError({
        code: "no-default-version",
        packageName: name,
        ecosystem: "pypi",
        requestedVersion,
        availableVersions
      });
    }

    if (!document.releases?.[version]) {
      throw new RegistryError({
        code: "unknown-version",
        packageName: name,
        ecosystem: "pypi",
        requestedVersion: version,
        availableVersions
      });
    }

    const release = document.releases?.[version]?.find((entry) => entry.url?.endsWith(".tar.gz")) ?? document.releases?.[version]?.[0];
    return {
      ecosystem: "pypi",
      name: document.info?.name ?? name,
      version,
      packageSpec,
      tarballUrl: release?.url,
      publishDate: release?.upload_time_iso_8601,
      maintainers: [document.info?.author, document.info?.maintainer].filter(Boolean) as string[],
      dependencies: {},
      installScripts: {},
      manifest: {
        name: document.info?.name ?? name,
        version
      },
      raw: document as Record<string, unknown>
    };
  }

  async getPreviousVersion(name: string, currentVersion: string): Promise<string | undefined> {
    const encoded = name.startsWith("@") ? name.replace("/", "%2f") : encodeURIComponent(name);
    const result = await fetchJson<NpmRegistryDocument>(`https://registry.npmjs.org/${encoded}`);
    if (!result.ok) {
      return undefined;
    }
    return this.getPreviousVersionFromDocument(currentVersion, result.data);
  }

  private pickInstallScripts(scripts: Record<string, string> | undefined): Record<string, string> {
    if (!scripts) {
      return {};
    }

    const interesting = ["preinstall", "install", "postinstall", "prepare"];
    return Object.fromEntries(Object.entries(scripts).filter(([name]) => interesting.includes(name)));
  }

  private getPreviousVersionFromDocument(version: string, document: NpmRegistryDocument): string | undefined {
    const versions = Object.keys(document.versions ?? {}).filter((candidate) => semver.valid(candidate));
    const sorted = versions.sort(semver.compare);
    const index = sorted.indexOf(version);
    if (index <= 0) {
      return undefined;
    }

    return sorted[index - 1];
  }
}
