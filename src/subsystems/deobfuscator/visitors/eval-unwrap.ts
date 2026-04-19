import { parse } from "@babel/parser";
import traverseImport from "@babel/traverse";
import * as t from "@babel/types";

import type { DeobfuscationContext } from "../pipeline.js";

const traverse = (traverseImport as any).default ?? traverseImport;

const PARSER_PLUGINS = [
  "jsx",
  "typescript",
  "classProperties",
  "dynamicImport",
  "topLevelAwait",
  "optionalChaining"
] as const;

function parseStatements(source: string): t.Statement[] | null {
  try {
    return parse(source, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      errorRecovery: true,
      plugins: [...PARSER_PLUGINS]
    }).program.body;
  } catch {
    return null;
  }
}

function extractFunctionBody(node: t.CallExpression): string | null {
  if (!t.isNewExpression(node.callee) || !t.isIdentifier(node.callee.callee, { name: "Function" })) {
    return null;
  }

  const args = node.callee.arguments;
  const body = args[args.length - 1];
  if (!body || !t.isStringLiteral(body)) {
    return null;
  }

  return body.value;
}

export function runEvalUnwrapVisitor(ast: t.File, context: DeobfuscationContext): void {
  traverse(ast, {
    ExpressionStatement(path: any) {
      const expression = path.node.expression;
      if (
        t.isCallExpression(expression) &&
        t.isIdentifier(expression.callee, { name: "eval" }) &&
        expression.arguments.length === 1 &&
        t.isStringLiteral(expression.arguments[0])
      ) {
        const statements = parseStatements(expression.arguments[0].value);
        if (statements) {
          path.replaceWithMultiple(statements);
          context.noteString(expression.arguments[0].value);
        }
        return;
      }

      if (t.isCallExpression(expression)) {
        const body = extractFunctionBody(expression);
        if (!body) {
          return;
        }

        const normalized = body.trim().startsWith("return ") ? body.trim().slice("return ".length) : body;
        const statements = parseStatements(normalized.endsWith(";") ? normalized : `${normalized};`);
        if (statements) {
          path.replaceWithMultiple(statements);
          context.noteString(body);
        }
      }
    }
  });
}
