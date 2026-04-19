import type {
  EnvAccessEvent,
  FileWriteEvent,
  NetworkEvent,
  ProcessSpawnEvent,
  TraceEvent
} from "../../core/types.js";

const TOKEN_NAMES = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "NPM_TOKEN",
  "NODE_AUTH_TOKEN",
  "PYPI_TOKEN"
];

function normalizeLine(line: string): string {
  return line.replace(/^\[pid\s+\d+\]\s+/, "").trim();
}

function extractQuotedArgs(rawArgs: string): string[] {
  return [...rawArgs.matchAll(/"([^"]*)"/g)].map((match) => match[1]);
}

export class StraceParser {
  parse(rawTrace: string): TraceEvent[] {
    const events: TraceEvent[] = [];
    const fdToPath = new Map<string, string>();

    for (const rawLine of rawTrace.split("\n")) {
      const line = normalizeLine(rawLine);
      if (!line) {
        continue;
      }

      const openMatch = line.match(/(?:open|openat)\([^"]*"(?<path>[^"]+)".*?(?<flags>O_[A-Z_|]+).*?=\s*(?<fd>-?\d+)/);
      if (openMatch?.groups?.fd && Number(openMatch.groups.fd) >= 0) {
        const path = openMatch.groups.path;
        const flags = openMatch.groups.flags;
        fdToPath.set(openMatch.groups.fd, path);

        if (path === "/proc/self/environ") {
          events.push({
            type: "env_access",
            raw: rawLine
          });
        } else if (flags.includes("O_WRONLY") || flags.includes("O_RDWR") || flags.includes("O_CREAT")) {
          events.push({
            type: "file_write",
            path,
            raw: rawLine
          });
        } else if (this.shouldTrackRead(path)) {
          events.push({
            type: "file_read",
            path,
            raw: rawLine
          });
        }

        continue;
      }

      const writeMatch = line.match(/write\((?<fd>\d+),\s*"(?<data>.*)",\s*\d+\)\s*=/);
      const writeGroups = writeMatch?.groups;
      if (writeGroups?.fd && writeGroups.data !== undefined) {
        const path = fdToPath.get(writeGroups.fd);
        if (path) {
          events.push({
            type: "file_write",
            path,
            content: writeGroups.data.slice(0, 512),
            raw: rawLine
          });
        }

        const envVars = TOKEN_NAMES.filter((name) => writeGroups.data.includes(name));
        for (const variable of envVars) {
          events.push({
            type: "env_access",
            variable,
            raw: rawLine
          });
        }

        continue;
      }

      const connectMatch = line.match(
        /(?<syscall>connect|sendto)\(\d+,\s*\{.*?(?:sin_port|sin6_port)=htons\((?<port>\d+)\).*?(?:"(?<address>[^"]+)").*\}\s*,/
      );
      if (connectMatch?.groups?.address && connectMatch.groups.port) {
        events.push({
          type: "network",
          syscall: connectMatch.groups.syscall,
          address: connectMatch.groups.address,
          port: Number(connectMatch.groups.port),
          raw: rawLine
        });
        continue;
      }

      const execMatch = line.match(/execve\("(?<command>[^"]+)",\s*\[(?<args>.*)\],/);
      if (execMatch?.groups?.command) {
        events.push({
          type: "process_spawn",
          command: execMatch.groups.command,
          args: extractQuotedArgs(execMatch.groups.args),
          raw: rawLine
        });
        continue;
      }

      if (line.includes("/proc/self/environ")) {
        events.push({
          type: "env_access",
          raw: rawLine
        });
      }
    }

    return this.deduplicate(events);
  }

  summarize(events: TraceEvent[]): {
    networkAttempts: NetworkEvent[];
    fileWrites: FileWriteEvent[];
    processSpawns: ProcessSpawnEvent[];
    envAccesses: EnvAccessEvent[];
  } {
    return {
      networkAttempts: events
        .filter((event): event is Extract<TraceEvent, { type: "network" }> => event.type === "network")
        .map((event) => ({
          address: event.address,
          port: event.port,
          syscall: event.syscall,
          evidence: event.raw
        })),
      fileWrites: events
        .filter((event): event is Extract<TraceEvent, { type: "file_write" }> => event.type === "file_write")
        .map((event) => ({
          path: event.path,
          content: event.content,
          evidence: event.raw
        })),
      processSpawns: events
        .filter((event): event is Extract<TraceEvent, { type: "process_spawn" }> => event.type === "process_spawn")
        .map((event) => ({
          command: event.command,
          args: event.args,
          evidence: event.raw
        })),
      envAccesses: events
        .filter((event): event is Extract<TraceEvent, { type: "env_access" }> => event.type === "env_access")
        .map((event) => ({
          variable: event.variable,
          evidence: event.raw
        }))
    };
  }

  private shouldTrackRead(path: string): boolean {
    return [".npmrc", ".pypirc", ".ssh", ".aws", "/proc/self/environ", ".github/workflows"].some((needle) => path.includes(needle));
  }

  private deduplicate(events: TraceEvent[]): TraceEvent[] {
    const seen = new Set<string>();
    return events.filter((event) => {
      const key = JSON.stringify(event);
      if (seen.has(key)) {
        return false;
      }

      seen.add(key);
      return true;
    });
  }
}
