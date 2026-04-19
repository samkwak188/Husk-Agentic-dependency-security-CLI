import type { AgentExecutionResult, HuskVerdict } from "../core/types.js";
import { getAIWorkflowClient } from "./ai-workflow.js";

export class ReporterAgent {
  private readonly workflow = getAIWorkflowClient();

  async generate(verdict: HuskVerdict): Promise<AgentExecutionResult<string>> {
    const fallback = this.template(verdict);
    if (verdict.verdict === "CLEAN") {
      return {
        value: fallback,
        stage: {
          mode: "deterministic"
        }
      };
    }

    const text = await this.workflow.createTextResponse({
      stage: "reporting",
      instructions: [
        "You are Husk's security advisory writer.",
        "Write concise Markdown suitable for a supply-chain malware finding.",
        "Use short sections with clear operational recommendations.",
        "Always include a 'Safe Next Move' section with concrete, evidence-backed actions or safer alternatives.",
        "Do not invent indicators or remediation steps that are not supported by the evidence."
      ].join("\n"),
      input: [
        `Package: ${verdict.packageName}@${verdict.packageVersion}`,
        `Ecosystem: ${verdict.ecosystem}`,
        `Verdict: ${verdict.verdict}`,
        `Policy action: ${verdict.policy.action}`,
        `Policy summary: ${verdict.policy.summary}`,
        `Confidence: ${verdict.confidence}`,
        `Timestamp: ${verdict.timestamp}`,
        `Reasons: ${verdict.reasons.map((reason) => `${reason.severity} ${reason.title}: ${reason.evidence}`).join("; ") || "none"}`,
        `IOCs: ${verdict.iocs.map((ioc) => `${ioc.severity} ${ioc.description}: ${ioc.evidence}`).join("; ") || "none"}`,
        `Behavior diff: ${verdict.behaviorDiff ? JSON.stringify(verdict.behaviorDiff).slice(0, 5000) : "none"}`,
        `Deobfuscation: ${verdict.deobfuscation ? verdict.deobfuscation.deobfuscatedSource.slice(0, 2000) : "none"}`,
        `Dynamic narrative: ${verdict.narrative ?? "none"}`,
        `Recommendations: ${verdict.recommendations.join("; ") || "none"}`
      ].join("\n")
    });

    return {
      value: text ?? fallback,
      stage: this.workflow.describeStage("reporting")
    };
  }

  private template(verdict: HuskVerdict): string {
    const reasonLines = verdict.reasons.map((reason) => `- [${reason.severity}] ${reason.title}: ${reason.evidence}`);
    const recommendationLines = verdict.recommendations.map((recommendation) => `- ${recommendation}`);
    const diffLines = verdict.behaviorDiff
      ? [
          "### Behavior Diff",
          ...verdict.behaviorDiff.newCapabilities.slice(0, 5).map((capability) => `- New ${capability.type}: ${capability.detail}`)
        ]
      : [];
    const deobfuscatedBlock =
      verdict.deobfuscation && verdict.deobfuscation.deobfuscatedSource !== verdict.deobfuscation.originalSource
        ? [
            "### Deobfuscated Payload",
            "```javascript",
            verdict.deobfuscation.deobfuscatedSource.slice(0, 1200),
            "```"
          ]
        : [];

    return [
      `## ${verdict.verdict === "MALICIOUS" ? "Malicious Package Detected" : "Package Scan Result"}`,
      "",
      `**Package**: ${verdict.packageName}@${verdict.packageVersion}`,
      `**Ecosystem**: ${verdict.ecosystem}`,
      `**Verdict**: ${verdict.verdict} (confidence: ${verdict.confidence})`,
      `**Policy Action**: ${verdict.policy.action}`,
      `**Scan Date**: ${verdict.timestamp}`,
      "",
      "### Indicators of Compromise",
      ...(reasonLines.length ? reasonLines : ["- No high-confidence indicators captured."]),
      "",
      ...diffLines,
      "",
      ...deobfuscatedBlock,
      "",
      "### Safe Next Move",
      ...(recommendationLines.length
        ? recommendationLines
        : [
            verdict.verdict === "CLEAN"
              ? "No blocking action recommended. Continue monitoring future updates."
              : "Do not install this package until it has been manually reviewed."
          ])
    ]
      .filter(Boolean)
      .join("\n");
  }
}
