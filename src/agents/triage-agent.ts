import { z } from "zod";

import type { AgentExecutionResult, PackageMetadata, TriageDecision, TyposquatResult } from "../core/types.js";
import { getAIWorkflowClient } from "./ai-workflow.js";

const triageDecisionSchema = z.object({
  runSandbox: z.boolean(),
  runDeobfuscator: z.boolean(),
  runDiff: z.boolean(),
  reason: z.string().min(1).max(500)
});

export class TriageAgent {
  private readonly workflow = getAIWorkflowClient();

  async decide(metadata: PackageMetadata, typosquat: TyposquatResult | null): Promise<AgentExecutionResult<TriageDecision>> {
    const fallback = this.deterministic(metadata, typosquat);
    const parsed = await this.workflow.createStructuredResponse({
      stage: "triage",
      schemaName: "husk_triage_decision",
      schema: triageDecisionSchema,
      instructions: [
        "You are Husk's triage agent for supply-chain malware scanning.",
        "Return only the structured decision requested by the schema.",
        "Prefer higher analysis depth when package risk is ambiguous.",
        "Use the package metadata, lifecycle scripts, typosquat evidence, and release recency to decide which scanners should run."
      ].join("\n"),
      input: [
        `Package name: ${metadata.name}`,
        `Version: ${metadata.version}`,
        `Publish date: ${metadata.publishDate ?? "unknown"}`,
        `Maintainers: ${metadata.maintainers.join(", ") || "unknown"}`,
        `Previous version: ${metadata.previousVersion ?? "none"}`,
        `Dependencies count: ${Object.keys(metadata.dependencies).length}`,
        `Install scripts: ${JSON.stringify(metadata.installScripts)}`,
        `Typosquat signal: ${typosquat ? JSON.stringify(typosquat) : "none"}`,
        `Manifest excerpt: ${JSON.stringify(metadata.manifest).slice(0, 5000)}`
      ].join("\n")
    });

    if (!parsed) {
      return {
        value: fallback,
        stage: this.workflow.describeStage("triage")
      };
    }

    return {
      value: {
        runSandbox: parsed.runSandbox,
        runDeobfuscator: parsed.runDeobfuscator,
        runDiff: parsed.runDiff,
        reason: parsed.reason || fallback.reason
      },
      stage: this.workflow.describeStage("triage")
    };
  }

  private deterministic(metadata: PackageMetadata, typosquat: TyposquatResult | null): TriageDecision {
    const hasInstallScripts = Object.keys(metadata.installScripts).length > 0;
    const recentPublish = metadata.publishDate ? Date.now() - new Date(metadata.publishDate).getTime() < 7 * 24 * 60 * 60 * 1000 : false;
    const hasNativeHints = [".node", ".wasm"].some((needle) => JSON.stringify(metadata.manifest).includes(needle));

    return {
      runSandbox: hasInstallScripts || hasNativeHints,
      runDeobfuscator: hasInstallScripts || recentPublish || Boolean(typosquat),
      runDiff: Boolean(metadata.previousVersion),
      reason: [
        hasInstallScripts ? "install scripts present" : null,
        recentPublish ? "recently published" : null,
        hasNativeHints ? "native or wasm assets referenced" : null,
        typosquat ? `typosquat signal against ${typosquat.target}` : null,
        metadata.previousVersion ? `diff against ${metadata.previousVersion}` : null
      ]
        .filter(Boolean)
        .join("; ") || "baseline static analysis only"
    };
  }
}
