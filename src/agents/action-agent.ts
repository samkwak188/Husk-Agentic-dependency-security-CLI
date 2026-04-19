import { z } from "zod";

import type { AgentExecutionResult, HuskVerdict } from "../core/types.js";
import { getAIWorkflowClient } from "./ai-workflow.js";

const HeadlineSchema = z.enum(["SAFE TO INSTALL", "BE CAREFUL", "DO NOT INSTALL"]);

export const UserActionSchema = z.object({
  headline: HeadlineSchema,
  what_it_does: z
    .string()
    .min(5)
    .max(220)
    .describe("One plain-English sentence describing what this package is, written for a non-technical reader."),
  why: z
    .string()
    .min(10)
    .max(420)
    .describe("One or two plain-English sentences explaining why this verdict was reached. No jargon."),
  next_step: z
    .string()
    .min(10)
    .max(220)
    .describe("One plain-English sentence telling the user exactly what to do next."),
  command: z
    .string()
    .max(160)
    .nullable()
    .describe("A single safe shell command the user can copy-paste, or null if no command is needed.")
});

export type UserAction = z.infer<typeof UserActionSchema>;

export class ActionAgent {
  private readonly workflow = getAIWorkflowClient();

  async recommend(verdict: HuskVerdict): Promise<AgentExecutionResult<UserAction>> {
    const fallback = this.fallback(verdict);

    const response = await this.workflow.createStructuredResponse({
      stage: "reporting",
      schemaName: "user_action",
      schema: UserActionSchema,
      instructions: [
        "You are Husk's user-facing safety advisor.",
        "Write for a non-technical developer who just typed an install command.",
        "Be concrete, calm, and specific. Avoid security jargon (no words like 'IOC', 'TTPs', 'CVE').",
        "Use everyday words. Short sentences. Active voice.",
        "Pick the headline that best matches the verdict and policy:",
        "  CLEAN/ALLOW -> 'SAFE TO INSTALL'",
        "  SUSPICIOUS or WARN -> 'BE CAREFUL'",
        "  MALICIOUS or BLOCK -> 'DO NOT INSTALL'",
        "If you suggest a shell command, prefer safe, read-only commands (npm view, npm install --ignore-scripts, etc.).",
        "Never invent findings or recommend actions that contradict the evidence."
      ].join("\n"),
      input: this.summarizeForPrompt(verdict)
    });

    if (!response) {
      return { value: fallback, stage: this.workflow.describeStage("reporting") };
    }

    return { value: response, stage: this.workflow.describeStage("reporting") };
  }

  private summarizeForPrompt(verdict: HuskVerdict): string {
    const findings = verdict.reasons
      .slice(0, 6)
      .map((reason) => `- [${reason.severity}] ${reason.title}: ${reason.evidence}`)
      .join("\n");

    return [
      `Package: ${verdict.packageName}@${verdict.packageVersion} (${verdict.ecosystem})`,
      `Verdict: ${verdict.verdict}`,
      `Policy: ${verdict.policy.action} (${verdict.policy.summary})`,
      `Confidence: ${verdict.confidence}`,
      `Typosquat target: ${verdict.typosquat?.target ?? "none"}`,
      "",
      "Findings:",
      findings || "- (no high-signal findings)"
    ].join("\n");
  }

  private fallback(verdict: HuskVerdict): UserAction {
    const action = verdict.policy?.action ?? "ALLOW";

    if (verdict.verdict === "MALICIOUS" || action === "BLOCK") {
      const typosquat = verdict.typosquat
        ? ` It looks like a fake version of "${verdict.typosquat.target}".`
        : "";
      return {
        headline: "DO NOT INSTALL",
        what_it_does: `${verdict.packageName} is a ${verdict.ecosystem} package that triggered Husk's strongest warnings.${typosquat}`,
        why: "Husk found multiple serious signals (for example, attempts to read credentials, contact untrusted servers, or modify your CI). Installing this could compromise your machine.",
        next_step: typosquat
          ? `Cancel the install and use the real package "${verdict.typosquat?.target}" instead.`
          : "Cancel the install and report the package to the registry's security team if you can.",
        command: typosquat ? `npm view ${verdict.typosquat?.target}` : `npm view ${verdict.packageName}`
      };
    }

    if (verdict.verdict === "SUSPICIOUS" || action === "WARN") {
      return {
        headline: "BE CAREFUL",
        what_it_does: `${verdict.packageName} is a ${verdict.ecosystem} package that mostly looks normal, but a few signals stood out.`,
        why: "Husk saw something unusual but not clearly malicious. It might be safe, or it might be hiding behavior that only runs after install.",
        next_step: "Review the maintainer's profile and recent versions before installing. If you must try it, install without running scripts.",
        command: `npm install --ignore-scripts ${verdict.packageName}@${verdict.packageVersion}`
      };
    }

    return {
      headline: "SAFE TO INSTALL",
      what_it_does: `${verdict.packageName} is a ${verdict.ecosystem} package and Husk did not find malicious behavior.`,
      why: "All Husk's checks (known threat patterns, sandbox behavior, code obfuscation) came back clean for this version.",
      next_step: "You can install this package as planned.",
      command: `${verdict.ecosystem === "npm" ? "npm install" : "pip install"} ${verdict.packageName}${verdict.packageVersion ? (verdict.ecosystem === "npm" ? `@${verdict.packageVersion}` : `==${verdict.packageVersion}`) : ""}`
    };
  }
}
