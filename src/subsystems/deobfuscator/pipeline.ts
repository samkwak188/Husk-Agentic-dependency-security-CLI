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
    let ast = this.parse(currentCode);
    let converged = false;
    const deltas: DeobfuscationPassDelta[] = [];
    const allStrings = new Set<string>();
    const allSinks = new Set<string>();
    const allUrls = new Set<string>();

    for (let pass = 1; pass <= this.maxPasses; pass += 1) {
      const context = createContext();
      for (const visitor of this.visitors) {
        visitor(ast, context);
      }

      const nextCode = generate(ast, {
        comments: false,
        jsescOption: {
          minimal: true
        }
      }).code;

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
      ast = this.parse(currentCode);
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

  private parse(source: string): t.File {
    return parse(source, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      errorRecovery: true,
      plugins: [...PARSER_PLUGINS]
    });
  }
}
