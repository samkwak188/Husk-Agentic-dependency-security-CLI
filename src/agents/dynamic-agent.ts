import type { AgentExecutionResult, SandboxResult } from "../core/types.js";
import { getAIWorkflowClient } from "./ai-workflow.js";

export class DynamicAgent {
  private readonly workflow = getAIWorkflowClient();

  async narrate(packageName: string, sandboxResult: SandboxResult): Promise<AgentExecutionResult<string>> {
    const fallback = this.templateNarrative(packageName, sandboxResult);
    const text = await this.workflow.createTextResponse({
      stage: "dynamicNarration",
      instructions: [
        "You are Husk's dynamic-analysis narrator for supply-chain malware investigations.",
        "Write exactly 4 concise markdown bullet points.",
        "Be evidence-driven and avoid speculation beyond the provided events.",
        "Call out credential access, workflow tampering, outbound network activity, and process execution when present."
      ].join("\n"),
      input: [
        `Package: ${packageName}`,
        `Findings: ${sandboxResult.findings.map((finding) => `${finding.severity} ${finding.description}: ${finding.evidence}`).join("; ") || "none"}`,
        `Network attempts: ${sandboxResult.networkAttempts.map((event) => `${event.address}:${event.port} via ${event.syscall}`).join("; ") || "none"}`,
        `File writes: ${sandboxResult.fileWrites.map((event) => event.path).join("; ") || "none"}`,
        `Process spawns: ${sandboxResult.processSpawns.map((event) => [event.command, ...event.args].join(" ")).join(" | ") || "none"}`,
        `Environment accesses: ${sandboxResult.envAccesses.map((event) => event.variable ?? event.evidence).join("; ") || "none"}`
      ].join("\n")
    });

    return {
      value: text ?? fallback,
      stage: this.workflow.describeStage("dynamicNarration")
    };
  }

  private templateNarrative(packageName: string, sandboxResult: SandboxResult): string {
    const lines = [
      `- During installation of ${packageName}, Husk observed ${sandboxResult.traceEvents.length} traced events.`,
      sandboxResult.networkAttempts.length
        ? `- Network activity: ${sandboxResult.networkAttempts.map((event) => `${event.address}:${event.port}`).join(", ")}.`
        : "- Network activity: none observed.",
      sandboxResult.fileWrites.length
        ? `- File writes: ${sandboxResult.fileWrites.map((event) => event.path).slice(0, 5).join(", ")}.`
        : "- File writes: none observed.",
      sandboxResult.processSpawns.length
        ? `- Process spawns: ${sandboxResult.processSpawns.map((event) => [event.command, ...event.args].join(" ")).slice(0, 3).join(" | ")}.`
        : "- Process spawns: none observed."
    ];

    if (sandboxResult.findings.length) {
      lines.push(`- Flagged behavior: ${sandboxResult.findings.map((finding) => `${finding.severity} ${finding.description}`).join("; ")}.`);
    }

    return lines.join("\n");
  }
}
