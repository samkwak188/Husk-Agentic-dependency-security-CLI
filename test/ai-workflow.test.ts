import { describe, expect, it } from "vitest";

import { resolveAIWorkflowProviderConfig } from "../src/agents/ai-workflow.js";

describe("resolveAIWorkflowProviderConfig", () => {
  it("prefers OpenAI by default when both providers are present", () => {
    const config = resolveAIWorkflowProviderConfig({
      OPENAI_API_KEY: "openai-key",
      OPENROUTER_API_KEY: "openrouter-key"
    } as NodeJS.ProcessEnv);

    expect(config?.provider).toBe("openai");
    expect(config?.transport).toBe("responses");
    expect(config?.stageConfigs.reporting.model).toBe("gpt-5.4-mini");
  });

  it("selects OpenRouter when explicitly requested", () => {
    const config = resolveAIWorkflowProviderConfig({
      AI_PROVIDER: "openrouter",
      OPENROUTER_API_KEY: "openrouter-key",
      OPENROUTER_MODEL_TRIAGE: "anthropic/claude-sonnet-4.5",
      OPENROUTER_MODEL_TRIAGE_FALLBACKS: "openai/gpt-4.1-mini, openrouter/auto",
      OPENROUTER_HTTP_REFERER: "http://localhost:3000",
      OPENROUTER_APP_TITLE: "Husk"
    } as NodeJS.ProcessEnv);

    expect(config?.provider).toBe("openrouter");
    expect(config?.transport).toBe("chat_completions");
    expect(config?.stageConfigs.triage.model).toBe("anthropic/claude-sonnet-4.5");
    expect(config?.stageConfigs.triage.fallbackModels).toEqual(["openai/gpt-4.1-mini", "openrouter/auto"]);
    expect(config?.defaultHeaders).toEqual({
      "HTTP-Referer": "http://localhost:3000",
      "X-Title": "Husk"
    });
  });
});
