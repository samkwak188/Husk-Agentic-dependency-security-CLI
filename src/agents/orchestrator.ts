import { PackageFetcher } from "../core/package-fetcher.js";
import { PolicyEngine } from "../core/policy.js";
import type { AgentWorkflowSummary, HuskVerdict, OrchestratorOptions, ScanEvent } from "../core/types.js";
import { BehaviorDiffEngine } from "../subsystems/behavior-diff/index.js";
import { IOCMatcher } from "../subsystems/ioc-matcher/index.js";
import { analyzePackageShape } from "../subsystems/package-shape/index.js";
import { SandboxManager, isSandboxReady } from "../subsystems/sandbox/docker-manager.js";
import { TyposquatDetector } from "../subsystems/typosquat/index.js";
import { ActionAgent } from "./action-agent.js";
import { DeobfuscatorAgent } from "./deobfuscator-agent.js";
import { DynamicAgent } from "./dynamic-agent.js";
import { applyInvestigation, InvestigatorAgent } from "./investigator-agent.js";
import { ReporterAgent } from "./reporter-agent.js";
import { TriageAgent } from "./triage-agent.js";
import { VerdictAgent } from "./verdict-agent.js";

function emit(emitEvent: OrchestratorOptions["emitEvent"], event: ScanEvent): void {
  emitEvent?.(event);
}

export class HuskOrchestrator {
  private readonly fetcher = new PackageFetcher();
  private readonly iocMatcher = new IOCMatcher();
  private readonly typosquatDetector = new TyposquatDetector();
  private readonly triageAgent = new TriageAgent();
  private readonly deobfuscatorAgent = new DeobfuscatorAgent();
  private readonly behaviorDiffEngine = new BehaviorDiffEngine();
  private readonly verdictAgent = new VerdictAgent();
  private readonly investigatorAgent = new InvestigatorAgent();
  private readonly reporterAgent = new ReporterAgent();
  private readonly dynamicAgent = new DynamicAgent();
  private readonly actionAgent = new ActionAgent();
  private readonly policyEngine = new PolicyEngine();

  async analyze(packageSpec: string, options: OrchestratorOptions = {}): Promise<HuskVerdict> {
    const startedAt = Date.now();
    const timings: Record<string, number> = {};
    const mark = (stage: string, since: number) => {
      timings[stage] = Date.now() - since;
    };
    const progress = (stage: string, message: string) => {
      emit(options.emitEvent, {
        type: "scan:progress",
        packageSpec,
        timestamp: new Date().toISOString(),
        payload: { stage, message }
      });
    };

    emit(options.emitEvent, {
      type: "scan:started",
      packageSpec,
      timestamp: new Date().toISOString()
    });

    progress("fetch", "Fetching package and metadata");
    const fetchStart = Date.now();
    const prepared = await this.fetcher.preparePackage(options.localPath ?? packageSpec, options.ecosystem);
    mark("fetch", fetchStart);

    try {
      const typosquat = prepared.metadata.ecosystem === "npm" ? this.typosquatDetector.check(prepared.metadata.name) : null;

      progress("triage", "Triaging risk profile");
      const triageStart = Date.now();
      const triageExecution = await this.triageAgent.decide(prepared.metadata, typosquat);
      mark("triage", triageStart);
      const triage = triageExecution.value;

      emit(options.emitEvent, {
        type: "scan:triage",
        packageSpec,
        timestamp: new Date().toISOString(),
        payload: triage as unknown as Record<string, unknown>
      });

      const sandboxSupported = prepared.metadata.ecosystem === "npm";
      const shouldRunSandbox = sandboxSupported && !options.disableSandbox && !options.staticOnly && (options.forceSandbox || triage.runSandbox);
      const canRunSandbox = shouldRunSandbox && (await isSandboxReady());

      if (options.forceSandbox && !canRunSandbox) {
        throw new Error("Sandbox execution was forced, but Docker Desktop or the 'husk-sandbox' image is not ready. Run 'npm run setup' first.");
      }

      const staticStart = Date.now();
      progress("static", "Running static analysis (IOCs, deobfuscation, behavior diff)");
      if (canRunSandbox) {
        progress("sandbox", "Sandbox running in Docker (may take up to 60s)");
      }

      const [iocMatches, deobfuscation, behaviorDiff, sandboxResult, packageShape] = await Promise.all([
        this.iocMatcher.match(prepared.extractDir, prepared.metadata),
        triage.runDeobfuscator
          ? this.deobfuscatorAgent.analyzePackage(prepared.extractDir)
          : Promise.resolve(undefined),
        triage.runDiff && prepared.metadata.ecosystem === "npm"
          ? this.behaviorDiffEngine.diff(
              prepared.metadata.name,
              prepared.metadata.version,
              prepared.metadata.previousVersion,
              prepared.extractDir
            )
          : Promise.resolve(undefined),
        canRunSandbox
          ? new SandboxManager().analyze(options.localPath ?? packageSpec, {
              allowNetwork: true
            })
          : Promise.resolve(undefined),
        // Always run shape analysis: it's millisecond-scale (one glob + a
        // handful of stat calls) and it's the only detector that catches
        // empty dependency-confusion stubs, which by definition have no
        // code for the other static analyzers to find.
        analyzePackageShape(prepared.extractDir, prepared.metadata)
      ]);
      mark(canRunSandbox ? "sandbox" : "static", staticStart);

      progress("verdict", "Computing verdict");
      const verdictStart = Date.now();
      let verdict = this.verdictAgent.decide({
        metadata: prepared.metadata,
        iocs: iocMatches,
        behaviorDiff,
        deobfuscation,
        sandboxResult,
        typosquat,
        packageShape
      });
      mark("verdict", verdictStart);

      // Autonomous re-investigation loop. Fires only when (a) AI is enabled
      // and (b) the verdict is borderline (low-confidence SUSPICIOUS, or
      // CLEAN with a suppressed signal). The investigator agent decides
      // *itself* whether to dig deeper, picks files to inspect, and
      // synthesizes findings into a verdict adjustment. Hard guards in
      // applyInvestigation prevent it from overriding CRITICAL signals or
      // applying low-confidence recommendations.
      progress("investigate", "Reviewing borderline signals");
      const investigateStart = Date.now();
      const investigation = await this.investigatorAgent.investigate({
        packagePath: prepared.extractDir,
        packageName: prepared.metadata.name,
        packageVersion: prepared.metadata.version,
        verdict
      });
      mark("investigate", investigateStart);
      verdict = applyInvestigation(verdict, investigation);

      verdict.scanDuration = Date.now() - startedAt;

      progress("narrative", sandboxResult ? "Drafting dynamic narrative" : "Drafting summary");
      const narrativeStart = Date.now();
      const narrativeExecution = sandboxResult
        ? await this.dynamicAgent.narrate(prepared.metadata.name, sandboxResult)
        : {
            value: triage.reason,
            stage: {
              mode: "deterministic" as const
            }
          };
      mark("narrative", narrativeStart);
      verdict.narrative = narrativeExecution.value;

      progress("policy", "Applying policy");
      const policyStart = Date.now();
      verdict.policy = await this.policyEngine.evaluate(verdict);
      mark("policy", policyStart);

      progress("report", "Generating advisory");
      const reportStart = Date.now();
      const advisoryExecution = await this.reporterAgent.generate(verdict);
      mark("report", reportStart);
      verdict.advisory = advisoryExecution.value;

      progress("action", "Drafting next-step recommendation");
      const actionStart = Date.now();
      const actionExecution = await this.actionAgent.recommend(verdict);
      mark("action", actionStart);
      verdict.userAction = actionExecution.value;

      verdict.workflow = this.buildWorkflowSummary(triageExecution.stage, narrativeExecution.stage, advisoryExecution.stage);
      verdict.stageTimings = timings;

      emit(options.emitEvent, {
        type: "scan:completed",
        packageSpec,
        timestamp: new Date().toISOString(),
        payload: {
          verdict: verdict.verdict,
          confidence: verdict.confidence
        }
      });

      return verdict;
    } catch (error) {
      emit(options.emitEvent, {
        type: "scan:error",
        packageSpec,
        timestamp: new Date().toISOString(),
        payload: {
          message: error instanceof Error ? error.message : String(error)
        }
      });
      throw error;
    } finally {
      await this.fetcher.cleanup(prepared).catch(() => undefined);
    }
  }

  private buildWorkflowSummary(
    triage: AgentWorkflowSummary["triage"],
    dynamicNarration: AgentWorkflowSummary["dynamicNarration"],
    reporting: AgentWorkflowSummary["reporting"]
  ): AgentWorkflowSummary {
    const stages = [triage, dynamicNarration, reporting];
    const apiEnabled = stages.some((stage) => stage.mode !== "deterministic");
    const provider = stages.find((stage) => stage.provider)?.provider ?? "deterministic";
    return {
      provider,
      apiEnabled,
      triage,
      dynamicNarration,
      reporting
    };
  }
}
