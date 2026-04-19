import OpenAI from "openai";
import { zodResponseFormat, zodTextFormat } from "openai/helpers/zod";
import type { ReasoningEffort } from "openai/resources/shared.js";
import { z } from "zod";

import type { AgentWorkflowStage } from "../core/types.js";

type WorkflowStageName = "triage" | "dynamicNarration" | "reporting" | "investigation";
type SupportedAIProvider = "openai" | "openrouter";
type ProviderTransport = "responses" | "chat_completions";

interface StageConfig {
  model: string;
  fallbackModels: string[];
  reasoningEffort: Exclude<ReasoningEffort, null>;
  maxOutputTokens: number;
}

interface ProviderStageDefaults {
  triage: StageConfig;
  dynamicNarration: StageConfig;
  reporting: StageConfig;
  investigation: StageConfig;
}

interface ProviderRuntimeConfig {
  provider: SupportedAIProvider;
  transport: ProviderTransport;
  apiKey: string;
  baseURL?: string;
  defaultHeaders?: Record<string, string>;
  stageConfigs: ProviderStageDefaults;
}

class AIWorkflowOperationError extends Error {
  status?: number;
  type?: string;
  code?: string;
  headers?: unknown;
  retriable?: boolean;

  constructor(
    message: string,
    details: {
      status?: number;
      type?: string;
      code?: string;
      headers?: unknown;
      retriable?: boolean;
    } = {}
  ) {
    super(message);
    this.name = "AIWorkflowOperationError";
    this.status = details.status;
    this.type = details.type;
    this.code = details.code;
    this.headers = details.headers;
    this.retriable = details.retriable;
  }
}

const OPENAI_STAGE_DEFAULTS: ProviderStageDefaults = {
  triage: {
    model: "gpt-5.4",
    fallbackModels: [],
    reasoningEffort: "low",
    maxOutputTokens: 400
  },
  dynamicNarration: {
    model: "gpt-5.4-mini",
    fallbackModels: [],
    reasoningEffort: "low",
    maxOutputTokens: 500
  },
  reporting: {
    model: "gpt-5.4-mini",
    fallbackModels: [],
    reasoningEffort: "medium",
    maxOutputTokens: 900
  },
  // The investigation stage runs the autonomous re-investigation loop.
  // It only fires on borderline verdicts (~10-15% of scans), so it can
  // afford a slightly larger reasoning budget without dragging the
  // common-case scan time.
  investigation: {
    model: "gpt-5.4-mini",
    fallbackModels: [],
    reasoningEffort: "medium",
    maxOutputTokens: 700
  }
};

const OPENROUTER_FALLBACK_CHAIN = ["openai/gpt-4.1-mini", "openrouter/auto"];

const OPENROUTER_STAGE_DEFAULTS: ProviderStageDefaults = {
  triage: {
    model: "openai/gpt-4.1-mini",
    fallbackModels: OPENROUTER_FALLBACK_CHAIN,
    reasoningEffort: "low",
    maxOutputTokens: 400
  },
  dynamicNarration: {
    model: "openai/gpt-4.1-mini",
    fallbackModels: OPENROUTER_FALLBACK_CHAIN,
    reasoningEffort: "low",
    maxOutputTokens: 500
  },
  reporting: {
    model: "openai/gpt-4.1-mini",
    fallbackModels: OPENROUTER_FALLBACK_CHAIN,
    reasoningEffort: "medium",
    maxOutputTokens: 900
  },
  investigation: {
    model: "openai/gpt-4.1-mini",
    fallbackModels: OPENROUTER_FALLBACK_CHAIN,
    reasoningEffort: "medium",
    maxOutputTokens: 700
  }
};

const DEFAULT_MAX_RETRIES = Number(process.env.AI_MAX_RETRIES ?? process.env.OPENAI_MAX_RETRIES ?? 2);
const DEFAULT_RETRY_BASE_MS = Number(process.env.AI_RETRY_BASE_MS ?? process.env.OPENAI_RETRY_BASE_MS ?? 1200);

function truncate(value: string, maxChars: number): string {
  return value.length > maxChars ? `${value.slice(0, maxChars)}\n...[truncated by Husk]` : value;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function isFiniteNonNegative(value: number): boolean {
  return Number.isFinite(value) && value >= 0;
}

function parseRetryAfterMs(headers: unknown): number | undefined {
  if (!headers || typeof headers !== "object") {
    return undefined;
  }

  const retryAfter = Object.entries(headers).find(([key]) => key.toLowerCase() === "retry-after")?.[1];
  if (typeof retryAfter === "number") {
    return retryAfter * 1000;
  }

  if (typeof retryAfter !== "string") {
    return undefined;
  }

  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds)) {
    return seconds * 1000;
  }

  const timestamp = Date.parse(retryAfter);
  if (Number.isNaN(timestamp)) {
    return undefined;
  }

  return Math.max(0, timestamp - Date.now());
}

function getStageMode(provider: SupportedAIProvider, transport: ProviderTransport): AgentWorkflowStage["mode"] {
  if (provider === "openai" && transport === "responses") {
    return "openai_responses";
  }

  return "openrouter_chat_completions";
}

function normalizeConfiguredProvider(value: string | undefined): SupportedAIProvider | "auto" | undefined {
  if (!value) {
    return undefined;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "openai" || normalized === "openrouter" || normalized === "auto") {
    return normalized;
  }

  return undefined;
}

function normalizeModelList(values: Array<string | undefined>): string[] {
  const unique = new Set<string>();

  for (const value of values) {
    for (const candidate of (value ?? "").split(",")) {
      const trimmed = candidate.trim();
      if (trimmed) {
        unique.add(trimmed);
      }
    }
  }

  return Array.from(unique);
}

function getStageEnvCandidates(provider: SupportedAIProvider, stage: WorkflowStageName, env: NodeJS.ProcessEnv): Array<string | undefined> {
  const genericStageKey =
    stage === "triage" ? env.AI_MODEL_TRIAGE : stage === "dynamicNarration" ? env.AI_MODEL_DYNAMIC : env.AI_MODEL_REPORTER;
  const providerStageKey =
    provider === "openai"
      ? stage === "triage"
        ? env.OPENAI_MODEL_TRIAGE
        : stage === "dynamicNarration"
          ? env.OPENAI_MODEL_DYNAMIC
          : env.OPENAI_MODEL_REPORTER
      : stage === "triage"
        ? env.OPENROUTER_MODEL_TRIAGE
        : stage === "dynamicNarration"
          ? env.OPENROUTER_MODEL_DYNAMIC
          : env.OPENROUTER_MODEL_REPORTER;

  return [genericStageKey, providerStageKey, env.AI_MODEL, provider === "openai" ? env.OPENAI_MODEL : env.OPENROUTER_MODEL];
}

function getFallbackEnvCandidates(provider: SupportedAIProvider, stage: WorkflowStageName, env: NodeJS.ProcessEnv): Array<string | undefined> {
  const genericStageKey =
    stage === "triage"
      ? env.AI_MODEL_TRIAGE_FALLBACKS
      : stage === "dynamicNarration"
        ? env.AI_MODEL_DYNAMIC_FALLBACKS
        : env.AI_MODEL_REPORTER_FALLBACKS;
  const providerStageKey =
    provider === "openai"
      ? stage === "triage"
        ? env.OPENAI_MODEL_TRIAGE_FALLBACKS
        : stage === "dynamicNarration"
          ? env.OPENAI_MODEL_DYNAMIC_FALLBACKS
          : env.OPENAI_MODEL_REPORTER_FALLBACKS
      : stage === "triage"
        ? env.OPENROUTER_MODEL_TRIAGE_FALLBACKS
        : stage === "dynamicNarration"
          ? env.OPENROUTER_MODEL_DYNAMIC_FALLBACKS
          : env.OPENROUTER_MODEL_REPORTER_FALLBACKS;
  const providerGlobalKey = provider === "openai" ? env.OPENAI_MODEL_FALLBACKS : env.OPENROUTER_MODEL_FALLBACKS;

  return [genericStageKey, providerStageKey, env.AI_MODEL_FALLBACKS, providerGlobalKey];
}

function resolveStageConfig(
  provider: SupportedAIProvider,
  stage: WorkflowStageName,
  defaults: StageConfig,
  env: NodeJS.ProcessEnv
): StageConfig {
  const model = getStageEnvCandidates(provider, stage, env).find((candidate) => Boolean(candidate?.trim())) ?? defaults.model;
  const fallbackModels = normalizeModelList([...getFallbackEnvCandidates(provider, stage, env), ...defaults.fallbackModels]).filter(
    (candidate) => candidate !== model
  );

  return {
    ...defaults,
    model,
    fallbackModels
  };
}

export function resolveAIWorkflowProviderConfig(env: NodeJS.ProcessEnv = process.env): ProviderRuntimeConfig | undefined {
  const requestedProvider = normalizeConfiguredProvider(env.AI_PROVIDER);

  const selectOpenAI = (): ProviderRuntimeConfig | undefined => {
    if (!env.OPENAI_API_KEY) {
      return undefined;
    }

    return {
      provider: "openai",
      transport: "responses",
      apiKey: env.OPENAI_API_KEY,
      stageConfigs: {
        triage: resolveStageConfig("openai", "triage", OPENAI_STAGE_DEFAULTS.triage, env),
        dynamicNarration: resolveStageConfig("openai", "dynamicNarration", OPENAI_STAGE_DEFAULTS.dynamicNarration, env),
        reporting: resolveStageConfig("openai", "reporting", OPENAI_STAGE_DEFAULTS.reporting, env),
        investigation: resolveStageConfig("openai", "investigation", OPENAI_STAGE_DEFAULTS.investigation, env)
      }
    };
  };

  const selectOpenRouter = (): ProviderRuntimeConfig | undefined => {
    if (!env.OPENROUTER_API_KEY) {
      return undefined;
    }

    const defaultHeaders = Object.fromEntries(
      [
        ["HTTP-Referer", env.OPENROUTER_HTTP_REFERER],
        ["X-Title", env.OPENROUTER_APP_TITLE ?? "Husk"]
      ].filter((entry): entry is [string, string] => Boolean(entry[1]?.trim()))
    );

    return {
      provider: "openrouter",
      transport: "chat_completions",
      apiKey: env.OPENROUTER_API_KEY,
      baseURL: "https://openrouter.ai/api/v1",
      defaultHeaders: Object.keys(defaultHeaders).length ? defaultHeaders : undefined,
      stageConfigs: {
        triage: resolveStageConfig("openrouter", "triage", OPENROUTER_STAGE_DEFAULTS.triage, env),
        dynamicNarration: resolveStageConfig("openrouter", "dynamicNarration", OPENROUTER_STAGE_DEFAULTS.dynamicNarration, env),
        reporting: resolveStageConfig("openrouter", "reporting", OPENROUTER_STAGE_DEFAULTS.reporting, env),
        investigation: resolveStageConfig("openrouter", "investigation", OPENROUTER_STAGE_DEFAULTS.investigation, env)
      }
    };
  };

  if (requestedProvider === "openrouter") {
    return selectOpenRouter();
  }

  if (requestedProvider === "openai") {
    return selectOpenAI();
  }

  return selectOpenAI() ?? selectOpenRouter();
}

function extractChatMessageText(content: unknown): string | undefined {
  if (typeof content === "string") {
    const trimmed = content.trim();
    return trimmed ? trimmed : undefined;
  }

  if (!Array.isArray(content)) {
    return undefined;
  }

  const text = content
    .map((part) => {
      if (!part || typeof part !== "object") {
        return "";
      }

      const candidate = part as { type?: string; text?: string };
      return candidate.type === "text" && typeof candidate.text === "string" ? candidate.text : "";
    })
    .join("")
    .trim();

  return text ? text : undefined;
}

function createEmptyResponseError(provider: SupportedAIProvider, kind: "text" | "structured"): AIWorkflowOperationError {
  const label = provider === "openrouter" ? "OpenRouter" : "OpenAI";
  return new AIWorkflowOperationError(`${label} returned no ${kind} output.`, {
    code: "empty_response",
    retriable: false
  });
}

export class AIWorkflowClient {
  private readonly runtime = resolveAIWorkflowProviderConfig();
  private readonly client?: OpenAI;
  private readonly lastErrors = new Map<WorkflowStageName, NonNullable<AgentWorkflowStage["error"]>>();
  private readonly resolvedModels = new Map<WorkflowStageName, string>();

  constructor() {
    if (this.runtime) {
      this.client = new OpenAI({
        apiKey: this.runtime.apiKey,
        baseURL: this.runtime.baseURL,
        defaultHeaders: this.runtime.defaultHeaders
      });
    }
  }

  isEnabled(): boolean {
    return Boolean(this.client && this.runtime);
  }

  describeStage(stage: WorkflowStageName): AgentWorkflowStage {
    const config = this.runtime?.stageConfigs[stage];
    const error = this.lastErrors.get(stage);
    return {
      mode: this.runtime && !error ? getStageMode(this.runtime.provider, this.runtime.transport) : "deterministic",
      provider: this.runtime?.provider,
      model: this.resolvedModels.get(stage) ?? config?.model,
      error
    };
  }

  private clearStageError(stage: WorkflowStageName): void {
    this.lastErrors.delete(stage);
  }

  private setStageError(stage: WorkflowStageName, error: NonNullable<AgentWorkflowStage["error"]>): void {
    this.lastErrors.set(stage, error);
  }

  private classifyError(error: unknown, attempts: number): NonNullable<AgentWorkflowStage["error"]> {
    const candidate = error as {
      status?: number;
      type?: string;
      code?: string;
      message?: string;
      headers?: unknown;
      error?: {
        type?: string;
        code?: string;
        message?: string;
      };
      name?: string;
      retriable?: boolean;
    };
    const status = candidate?.status;
    const type = candidate?.error?.type ?? candidate?.type;
    const code = candidate?.error?.code ?? candidate?.code;
    const message = candidate?.error?.message ?? candidate?.message ?? String(error);
    const retriable =
      candidate?.retriable ??
      (status === 503 ||
        status === 408 ||
        (status === 429 && code !== "insufficient_quota") ||
        candidate?.name === "APIConnectionError" ||
        candidate?.name === "APITimeoutError");

    const retryAfterMs = parseRetryAfterMs(candidate?.headers);
    const retrySuffix = isFiniteNonNegative(retryAfterMs ?? NaN) ? ` (retry-after ${retryAfterMs}ms)` : "";

    return {
      status,
      type,
      code,
      message: `${message}${retrySuffix}`,
      retriable,
      attempts: isFiniteNonNegative(attempts) ? attempts : undefined
    };
  }

  private shouldRetry(stageError: NonNullable<AgentWorkflowStage["error"]>, attempts: number): boolean {
    return Boolean(stageError.retriable) && attempts <= DEFAULT_MAX_RETRIES;
  }

  private getModelCandidates(stage: WorkflowStageName): string[] {
    const config = this.runtime?.stageConfigs[stage];
    if (!config) {
      return [];
    }

    return normalizeModelList([config.model, ...config.fallbackModels]);
  }

  private async runWithRetry<T>(
    stage: WorkflowStageName,
    model: string,
    operation: (config: StageConfig, model: string) => Promise<T>
  ): Promise<{ value?: T; error?: NonNullable<AgentWorkflowStage["error"]> }> {
    if (!this.client || !this.runtime) {
      this.clearStageError(stage);
      return {};
    }

    const config = this.runtime.stageConfigs[stage];

    for (let attempts = 1; attempts <= DEFAULT_MAX_RETRIES + 1; attempts += 1) {
      try {
        return {
          value: await operation(config, model)
        };
      } catch (error) {
        const stageError = this.classifyError(error, attempts);
        if (!this.shouldRetry(stageError, attempts)) {
          return {
            error: stageError
          };
        }

        const retryAfterMs = parseRetryAfterMs((error as { headers?: unknown })?.headers);
        const backoffMs = isFiniteNonNegative(retryAfterMs ?? NaN)
          ? (retryAfterMs as number)
          : DEFAULT_RETRY_BASE_MS * Math.pow(2, attempts - 1);
        await delay(backoffMs);
      }
    }

    return {};
  }

  private async runAcrossModels<T>(
    stage: WorkflowStageName,
    kind: "text" | "structured",
    operation: (config: StageConfig, model: string) => Promise<T>
  ): Promise<T | undefined> {
    if (!this.runtime || !this.client) {
      this.clearStageError(stage);
      return undefined;
    }

    let lastError: NonNullable<AgentWorkflowStage["error"]> | undefined;

    for (const model of this.getModelCandidates(stage)) {
      const result = await this.runWithRetry(stage, model, operation);
      if (result.value !== undefined) {
        this.clearStageError(stage);
        this.resolvedModels.set(stage, model);
        return result.value;
      }

      if (result.error) {
        lastError = result.error;
      }
    }

    this.resolvedModels.delete(stage);
    this.setStageError(stage, lastError ?? this.classifyError(createEmptyResponseError(this.runtime.provider, kind), 1));
    return undefined;
  }

  async createStructuredResponse<T>(options: {
    stage: WorkflowStageName;
    schemaName: string;
    schema: z.ZodType<T>;
    instructions: string;
    input: string;
    maxOutputTokens?: number;
  }): Promise<T | undefined> {
    return this.runAcrossModels<T>(options.stage, "structured", async (config, model) => {
      if (!this.runtime || !this.client) {
        throw createEmptyResponseError("openrouter", "structured");
      }

      if (this.runtime.provider === "openrouter") {
        const response = await this.client.chat.completions.parse({
          model,
          messages: [
            { role: "system", content: options.instructions },
            { role: "user", content: truncate(options.input, 16_000) }
          ],
          max_completion_tokens: options.maxOutputTokens ?? config.maxOutputTokens,
          response_format: zodResponseFormat(options.schema, options.schemaName),
          plugins: [{ id: "response-healing" }],
          provider: {
            require_parameters: true
          }
        } as never);

        const parsedContent = response.choices[0]?.message.parsed as T | null | undefined;
        if (parsedContent == null) {
          throw createEmptyResponseError(this.runtime.provider, "structured");
        }

        return parsedContent;
      }

      const response = await this.client.responses.parse({
        model,
        instructions: options.instructions,
        input: truncate(options.input, 16_000),
        max_output_tokens: options.maxOutputTokens ?? config.maxOutputTokens,
        reasoning: {
          effort: config.reasoningEffort,
          summary: "concise"
        },
        text: {
          format: zodTextFormat(options.schema, options.schemaName)
        }
      });

      if (response.output_parsed == null) {
        throw createEmptyResponseError(this.runtime.provider, "structured");
      }

      return response.output_parsed;
    });
  }

  async createTextResponse(options: {
    stage: WorkflowStageName;
    instructions: string;
    input: string;
    maxOutputTokens?: number;
  }): Promise<string | undefined> {
    return this.runAcrossModels<string>(options.stage, "text", async (config, model) => {
      if (!this.runtime || !this.client) {
        throw createEmptyResponseError("openrouter", "text");
      }

      if (this.runtime.provider === "openrouter") {
        const response = await this.client.chat.completions.create({
          model,
          messages: [
            { role: "system", content: options.instructions },
            { role: "user", content: truncate(options.input, 20_000) }
          ],
          max_completion_tokens: options.maxOutputTokens ?? config.maxOutputTokens,
          provider: {
            require_parameters: true
          }
        } as never);

        const text = extractChatMessageText(response.choices[0]?.message?.content);
        if (!text) {
          throw createEmptyResponseError(this.runtime.provider, "text");
        }

        return text;
      }

      const response = await this.client.responses.create({
        model,
        instructions: options.instructions,
        input: truncate(options.input, 20_000),
        max_output_tokens: options.maxOutputTokens ?? config.maxOutputTokens,
        reasoning: {
          effort: config.reasoningEffort,
          summary: "concise"
        }
      });

      const responseText = response.output_text?.trim();
      if (!responseText) {
        throw createEmptyResponseError(this.runtime.provider, "text");
      }

      return responseText;
    });
  }
}

let sharedClient: AIWorkflowClient | undefined;

export function getAIWorkflowClient(): AIWorkflowClient {
  if (!sharedClient) {
    sharedClient = new AIWorkflowClient();
  }

  return sharedClient;
}
