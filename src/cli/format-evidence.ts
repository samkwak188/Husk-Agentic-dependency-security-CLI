import { z } from "zod";

import { getAIWorkflowClient } from "../agents/ai-workflow.js";
import type { VerdictReason } from "../core/types.js";

const EvidenceSummarySchema = z.object({
  summary: z.string().min(8).max(220)
});

const BASE64_RUN = /[A-Za-z0-9+/=]{40,}/g;
const HEX_RUN = /\b[a-f0-9]{40,}\b/gi;
const WHITESPACE = /\s{2,}/g;
const SOFT_LIMIT = 220;
const HARD_LIMIT = 600;

export function compactEvidence(text: string): string {
  if (!text) return "";
  let out = text
    .replace(/\u0000/g, "")
    .replace(BASE64_RUN, (match) => `<base64 ${match.length}B>`)
    .replace(HEX_RUN, (match) => `<hex ${match.length}B>`)
    .replace(WHITESPACE, " ")
    .trim();

  if (out.length > HARD_LIMIT) {
    const head = out.slice(0, Math.floor(HARD_LIMIT * 0.55));
    const tail = out.slice(out.length - Math.floor(HARD_LIMIT * 0.35));
    out = `${head} … ${tail}`;
  }
  return out;
}

async function summarizeWithAI(reason: VerdictReason, compacted: string): Promise<string | null> {
  try {
    const workflow = getAIWorkflowClient();
    const result = await workflow.createStructuredResponse({
      stage: "reporting",
      schemaName: "evidence_summary",
      schema: EvidenceSummarySchema,
      instructions: [
        "You are Husk's evidence summarizer.",
        "Summarize ONE finding for a non-technical developer who just typed an install command.",
        "Write ONE short sentence, under 200 characters.",
        "Mention the suspicious behavior, where it appears (if visible), and the destination or command (if visible).",
        "No jargon: do not use IOC, TTP, CVE, sink, or gadget."
      ].join("\n"),
      input: [
        `Severity: ${reason.severity}`,
        `Finding title: ${reason.title}`,
        "Evidence:",
        compacted
      ].join("\n"),
      maxOutputTokens: 220
    });
    return result?.summary?.trim() || null;
  } catch {
    return null;
  }
}

export async function formatEvidence(reason: VerdictReason, options: { useAI?: boolean } = {}): Promise<string> {
  const compacted = compactEvidence(reason.evidence);
  if (compacted.length <= SOFT_LIMIT) return compacted;
  if (options.useAI === false) return compacted;
  const summary = await summarizeWithAI(reason, compacted);
  return summary ?? compacted;
}

export function formatEvidenceSync(reason: VerdictReason): string {
  return compactEvidence(reason.evidence);
}
