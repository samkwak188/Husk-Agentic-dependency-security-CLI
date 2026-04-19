import { EventEmitter } from "node:events";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";

import { HuskOrchestrator } from "../agents/orchestrator.js";
import type { HuskVerdict, ScanEvent } from "../core/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const publicDir = resolve(__dirname, "public");
const history: HuskVerdict[] = [];
const emitter = new EventEmitter();

function broadcast(event: ScanEvent | { type: "scan:result"; payload: HuskVerdict }): void {
  emitter.emit("event", event);
}

function getStats() {
  const malicious = history.filter((entry) => entry.verdict === "MALICIOUS").length;
  const suspicious = history.filter((entry) => entry.verdict === "SUSPICIOUS").length;
  const avgScanTime = history.length ? history.reduce((sum, entry) => sum + entry.scanDuration, 0) / history.length : 0;
  const falsePositiveRate = history.length ? suspicious / history.length : 0;

  return {
    totalScanned: history.length,
    maliciousCaught: malicious,
    suspicious,
    falsePositiveRate: Number(falsePositiveRate.toFixed(2)),
    avgScanTime: Number(avgScanTime.toFixed(0))
  };
}

export async function startDashboardServer(port = Number(process.env.PORT ?? "3000")): Promise<void> {
  await mkdir(publicDir, { recursive: true });
  const app = express();
  const orchestrator = new HuskOrchestrator();

  app.use(express.json());
  app.use(express.static(publicDir));

  app.get("/api/stream", (request, response) => {
    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      Connection: "keep-alive",
      "Cache-Control": "no-cache"
    });

    const send = (event: unknown) => {
      response.write(`data: ${JSON.stringify(event)}\n\n`);
    };

    send({ type: "stats", payload: getStats() });
    const listener = (event: unknown) => send(event);
    emitter.on("event", listener);
    request.on("close", () => {
      emitter.off("event", listener);
    });
  });

  app.get("/api/results", (_request, response) => {
    response.json({
      history,
      stats: getStats()
    });
  });

  app.post("/api/scan", async (request, response) => {
    const packageSpec = typeof request.body?.packageSpec === "string" ? request.body.packageSpec : null;
    const localPath = typeof request.body?.localPath === "string" ? request.body.localPath : undefined;
    const forceSandbox = Boolean(request.body?.forceSandbox);

    if (!packageSpec && !localPath) {
      response.status(400).json({ error: "packageSpec or localPath is required" });
      return;
    }

    const target = localPath ?? packageSpec!;
    broadcast({
      type: "scan:queued",
      packageSpec: target,
      timestamp: new Date().toISOString()
    });

    void orchestrator
      .analyze(target, {
        localPath,
        forceSandbox,
        emitEvent: (event) => broadcast(event)
      })
      .then((verdict) => {
        history.unshift(verdict);
        history.splice(50);
        broadcast({ type: "scan:result", payload: verdict });
        broadcast({ type: "stats", payload: getStats() } as unknown as ScanEvent);
      })
      .catch((error) => {
        broadcast({
          type: "scan:error",
          packageSpec: target,
          timestamp: new Date().toISOString(),
          payload: {
            message: error instanceof Error ? error.message : String(error)
          }
        });
      });

    response.status(202).json({ ok: true, target });
  });

  await new Promise<void>((resolvePromise) => {
    app.listen(port, () => resolvePromise());
  });
  console.log(`Husk dashboard running at http://localhost:${port}`);
}

if (process.argv[1] && process.argv[1].endsWith("server.ts")) {
  void startDashboardServer();
}
