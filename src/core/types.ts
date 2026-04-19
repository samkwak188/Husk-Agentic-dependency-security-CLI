export type PackageEcosystem = "npm" | "pypi";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface PackageManifest {
  name?: string;
  version?: string;
  description?: string;
  main?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  repository?:
    | string
    | {
        type?: string;
        url?: string;
      };
  author?: string | Record<string, unknown>;
  maintainers?: Array<string | Record<string, unknown>>;
  keywords?: string[];
  husk?: Record<string, unknown>;
}

export interface PackageMetadata {
  ecosystem: PackageEcosystem;
  name: string;
  version: string;
  packageSpec: string;
  tarballUrl?: string;
  publishDate?: string;
  downloads?: number;
  previousVersion?: string;
  distTags?: Record<string, string>;
  maintainers: string[];
  dependencies: Record<string, string>;
  installScripts: Record<string, string>;
  manifest: PackageManifest;
  raw?: Record<string, unknown>;
}

export interface PreparedPackage {
  sourceType: "registry" | "local-dir" | "local-tarball";
  workspaceDir: string;
  extractDir: string;
  tarballPath: string;
  metadata: PackageMetadata;
}

export interface GroundTruthEntry {
  name: string;
  version: string;
  ecosystem: PackageEcosystem;
  label: "malicious";
  source: "datadog" | "backstabbers";
  category: "malicious_intent" | "compromised";
  zipPath: string;
  discoveryDate: string;
}

export interface SuspicionFinding {
  ruleId: string;
  severity: Severity;
  description: string;
  evidence: string;
}

export type TraceEvent =
  | {
      type: "network";
      syscall: string;
      address: string;
      port: number;
      data?: string;
      raw: string;
    }
  | {
      type: "file_write";
      path: string;
      content?: string;
      raw: string;
    }
  | {
      type: "file_read";
      path: string;
      raw: string;
    }
  | {
      type: "process_spawn";
      command: string;
      args: string[];
      raw: string;
    }
  | {
      type: "env_access";
      variable?: string;
      raw: string;
    };

export interface NetworkEvent {
  address: string;
  port: number;
  syscall: string;
  evidence: string;
}

export interface FileWriteEvent {
  path: string;
  content?: string;
  evidence: string;
}

export interface ProcessSpawnEvent {
  command: string;
  args: string[];
  evidence: string;
}

export interface EnvAccessEvent {
  variable?: string;
  evidence: string;
}

export interface SandboxResult {
  exitCode: number;
  traceEvents: TraceEvent[];
  installLog: string;
  duration: number;
  networkAttempts: NetworkEvent[];
  fileWrites: FileWriteEvent[];
  processSpawns: ProcessSpawnEvent[];
  envAccesses: EnvAccessEvent[];
  suspicious: boolean;
  suspicionReasons: string[];
  findings: SuspicionFinding[];
  rawTrace: string;
}

export interface DeobfuscationPassDelta {
  pass: number;
  changed: boolean;
  dangerousSinkCount: number;
  resolvedStringCount: number;
  wrapperInlineCount: number;
  revealedUrls: string[];
  revealedSinks: string[];
}

export interface DeobfuscationResult {
  sourceFile?: string;
  originalSource: string;
  deobfuscatedSource: string;
  passes: number;
  converged: boolean;
  suspicionScore: number;
  suspicionDeltas: DeobfuscationPassDelta[];
  revealedSinks: string[];
  revealedUrls: string[];
  revealedStrings: string[];
}

export interface TyposquatResult {
  target: string;
  distance: number;
  confidence: number;
  reasons: string[];
}

export type IOCRule =
  | {
      type: "filename";
      pattern: string;
      severity: Severity;
      description: string;
    }
  | {
      type: "content_regex";
      pattern: RegExp;
      severity: Severity;
      description: string;
    }
  | {
      type: "script_pattern";
      pattern: RegExp;
      severity: Severity;
      description: string;
    }
  | {
      type: "package_version";
      name: string;
      versions: string[];
      severity: Severity;
      description: string;
    }
  | {
      type: "domain";
      patterns: string[];
      severity: Severity;
      description: string;
    };

export interface IOCMatch {
  severity: Severity;
  ruleType: IOCRule["type"];
  description: string;
  evidence: string;
  file?: string;
}

export interface Capability {
  type: "network" | "filesystem" | "process" | "dependency" | "script" | "env";
  detail: string;
}

export interface FileDiff {
  path: string;
  changeType: "added" | "removed" | "changed";
}

export interface BehaviorDiff {
  packageName: string;
  candidateVersion: string;
  previousVersion: string;
  newCapabilities: Capability[];
  removedCapabilities: Capability[];
  changedFiles: FileDiff[];
  installScriptChanged: boolean;
  installScriptDiff?: string;
  suspicionScore: number;
}

export interface TriageDecision {
  runSandbox: boolean;
  runDeobfuscator: boolean;
  runDiff: boolean;
  reason: string;
}

export interface VerdictReason {
  severity: Severity;
  scoreImpact: number;
  title: string;
  evidence: string;
}

export interface AgentWorkflowStage {
  mode: "openai_responses" | "openrouter_chat_completions" | "deterministic";
  provider?: "openai" | "openrouter";
  model?: string;
  error?: {
    status?: number;
    type?: string;
    code?: string;
    message: string;
    retriable?: boolean;
    attempts?: number;
  };
}

export interface AgentWorkflowSummary {
  provider: "openai" | "openrouter" | "deterministic";
  apiEnabled: boolean;
  triage: AgentWorkflowStage;
  dynamicNarration: AgentWorkflowStage;
  reporting: AgentWorkflowStage;
}

export interface AgentExecutionResult<T> {
  value: T;
  stage: AgentWorkflowStage;
}

export type PolicyAction = "ALLOW" | "WARN" | "BLOCK";

export interface PolicyDecision {
  action: PolicyAction;
  summary: string;
  reasons: string[];
  policyName: string;
  canOverride: boolean;
  reviewRequired: boolean;
}

/**
 * Structural fingerprint of a package: how much code it actually ships,
 * what the file layout looks like, and whether the package name carries
 * patterns associated with dependency-confusion attacks. This is the
 * detector that catches "no-detector-fired" malicious packages — empty
 * stubs published to the public registry to hijack internal-package
 * resolution.
 */
export interface PackageShapeResult {
  totalSourceBytes: number;
  jsFileCount: number;
  hasReadme: boolean;
  hasMeaningfulCode: boolean;
  suspiciousNameSignals: string[];
  signal: "none" | "info" | "suspicious";
  reason: string;
}

/**
 * Trail of an autonomous re-investigation loop. Recorded only when the
 * verdict-agent's first-pass output is borderline (low confidence, single
 * MEDIUM signal, etc.) AND AI is enabled. This is the user-visible audit
 * record of "what did the agent decide to do, why, and what changed?".
 */
export interface InvestigationResult {
  triggered: boolean;
  reason: string;
  filesInspected: string[];
  focusQuestion?: string;
  recommendation: "promote-to-malicious" | "promote-to-suspicious" | "downgrade-to-clean" | "no-change";
  agentConfidence: number;
  rationale: string;
  durationMs: number;
}

export interface HuskVerdict {
  ecosystem: PackageEcosystem;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN";
  confidence: number;
  reasons: VerdictReason[];
  recommendations: string[];
  policy: PolicyDecision;
  iocs: IOCMatch[];
  behaviorDiff?: BehaviorDiff;
  deobfuscation?: DeobfuscationResult;
  sandboxResult?: SandboxResult;
  typosquat?: TyposquatResult | null;
  packageShape?: PackageShapeResult;
  investigation?: InvestigationResult;
  advisory?: string;
  narrative?: string;
  workflow: AgentWorkflowSummary;
  scanDuration: number;
  stageTimings?: Record<string, number>;
  userAction?: UserAction;
  timestamp: string;
  packageName: string;
  packageVersion: string;
}

export interface UserAction {
  headline: "SAFE TO INSTALL" | "BE CAREFUL" | "DO NOT INSTALL";
  what_it_does: string;
  why: string;
  next_step: string;
  command: string | null;
}

export interface OrchestratorOptions {
  ecosystem?: PackageEcosystem;
  forceSandbox?: boolean;
  disableSandbox?: boolean;
  staticOnly?: boolean;
  localPath?: string;
  emitEvent?: (event: ScanEvent) => void;
}

export interface ScanEvent {
  type:
    | "scan:queued"
    | "scan:started"
    | "scan:triage"
    | "scan:progress"
    | "scan:completed"
    | "scan:error";
  packageSpec: string;
  timestamp: string;
  payload?: Record<string, unknown>;
}
