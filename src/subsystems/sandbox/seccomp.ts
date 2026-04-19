import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const seccompUrl = new URL("../../../docker/seccomp-husk.json", import.meta.url);

export async function loadSeccompProfile(): Promise<string> {
  return readFile(fileURLToPath(seccompUrl), "utf8");
}

export function getSeccompProfilePath(): string {
  return fileURLToPath(seccompUrl);
}
