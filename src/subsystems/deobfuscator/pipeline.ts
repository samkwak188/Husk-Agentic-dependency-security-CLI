import { parse } from "@babel/parser";
import generateImport from "@babel/generator";
import type * as t from "@babel/types";

import type { DeobfuscationPassDelta, DeobfuscationResult } from "../../core/types.js";
import { calculateSuspicionScore, scoreSuspicion } from "./suspicion-scorer.js";
import { runConstantFoldVisitor } from "./visitors/constant-fold.js";
import { runEvalUnwrapVisitor } from "./visitors/eval-unwrap.js";
import { runStringArrayVisitor } from "./visitors/string-array.js";
import { runStringDecodeVisitor } from "./visitors/string-decode.js";
import { runWrapperInlineVisitor } from "./visitors/wrapper-inline.js";

const PARSER_PLUGINS = [
  "jsx",
  "typescript",
  "classProperties",
  "dynamicImport",
  "topLevelAwait",
  "optionalChaining"
] as const;

const generate = (generateImport as any).default ?? generateImport;

export interface DeobfuscationContext {
  changed: boolean;
  resolvedStrings: Set<string>;
  revealedSinks: Set<string>;
  revealedUrls: Set<string>;
  wrapperInlineCount: number;
  noteChange: () => void;
  noteString: (value: string) => void;
  noteInline: () => void;
}

type VisitorRunner = (ast: t.File, context: DeobfuscationContext) => void;

function createContext(): DeobfuscationContext {
  return {
    changed: false,
    resolvedStrings: new Set<string>(),
    revealedSinks: new Set<string>(),
    revealedUrls: new Set<string>(),
    wrapperInlineCount: 0,
    noteChange() {
      this.changed = true;
    },
    noteString(value: string) {
      this.changed = true;
      this.resolvedStrings.add(value);
    },
    noteInline() {
      this.changed = true;
      this.wrapperInlineCount += 1;
    }
  };
}

export class DeobfuscationPipeline {
  private readonly visitors: VisitorRunner[];
  private readonly maxPasses = 10;

  constructor() {
    this.visitors = [
      runStringDecodeVisitor,
      runStringArrayVisitor,
      runEvalUnwrapVisitor,
      runConstantFoldVisitor,
      runWrapperInlineVisitor
    ];
  }

  async deobfuscate(source: string): Promise<DeobfuscationResult> {
    let currentCode = source;
    let ast: t.File | null = this.tryParse(currentCode);
    let converged = false;
    const deltas: DeobfuscationPassDelta[] = [];
    const allStrings = new Set<string>();
    const allSinks = new Set<string>();
    const allUrls = new Set<string>();

    // If the initial parse failed (or any subsequent re-parse does), treat
    // the source as un-deobfuscatable rather than throwing — the rest of
    // the pipeline (suspicion scorer is regex-based) still works on raw
    // text, so we can return a useful fallback result.
    if (ast) {
      for (let pass = 1; pass <= this.maxPasses; pass += 1) {
        const context = createContext();
        for (const visitor of this.visitors) {
          // Wrap every visitor so a Babel scope-crawl failure or an
          // unexpected node shape in user code can't kill the entire
          // deobfuscation. We log nothing here on purpose — failures are
          // expected on real-world packages and would spam stderr.
          try {
            visitor(ast, context);
          } catch {
            // skip this visitor for this pass
          }
        }

        let nextCode: string;
        try {
          nextCode = generate(ast, {
            comments: false,
            jsescOption: {
              minimal: true
            }
          }).code;
        } catch {
          // Generator failures are rare but possible after partial AST
          // mutations. Fall back to the previous code text and stop iterating.
          nextCode = currentCode;
        }

        const summary = scoreSuspicion(nextCode);
        summary.sinks.forEach((sink) => allSinks.add(sink));
        summary.urls.forEach((url) => allUrls.add(url));
        context.resolvedStrings.forEach((value) => allStrings.add(value));

        deltas.push({
          pass,
          changed: context.changed && nextCode !== currentCode,
          dangerousSinkCount: summary.dangerousSinkCount,
          resolvedStringCount: context.resolvedStrings.size,
          wrapperInlineCount: context.wrapperInlineCount,
          revealedUrls: [...summary.urls],
          revealedSinks: [...summary.sinks]
        });

        if (nextCode === currentCode) {
          converged = true;
          currentCode = nextCode;
          break;
        }

        currentCode = nextCode;
        const reparsed = this.tryParse(currentCode);
        if (!reparsed) {
          // Re-parse failed on the mutated source — accept current text as
          // the final deobfuscated form rather than crashing.
          break;
        }
        ast = reparsed;
      }
    }

    return {
      originalSource: source,
      deobfuscatedSource: currentCode,
      passes: deltas.length,
      converged,
      suspicionScore: calculateSuspicionScore(currentCode),
      suspicionDeltas: deltas,
      revealedSinks: [...allSinks],
      revealedUrls: [...allUrls],
      revealedStrings: [...allStrings]
    };
  }

  private tryParse(source: string): t.File | null {
    try {
      return parse(source, {
        sourceType: "unambiguous",
        allowReturnOutsideFunction: true,
        errorRecovery: true,
        plugins: [...PARSER_PLUGINS]
      });
    } catch {
      return null;
    }
  }
}
