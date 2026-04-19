import traverseImport from "@babel/traverse";
import * as t from "@babel/types";

import type { DeobfuscationContext } from "../pipeline.js";

const traverse = (traverseImport as any).default ?? traverseImport;

function toLiteralNode(value: unknown): t.Expression | null {
  if (typeof value === "string") {
    return t.stringLiteral(value);
  }

  if (typeof value === "number") {
    return t.numericLiteral(value);
  }

  if (typeof value === "boolean") {
    return t.booleanLiteral(value);
  }

  if (value === null) {
    return t.nullLiteral();
  }

  return null;
}

export function runConstantFoldVisitor(ast: t.File, context: DeobfuscationContext): void {
  traverse(ast, {
    enter(path: any) {
      if (
        !path.isBinaryExpression() &&
        !path.isLogicalExpression() &&
        !path.isUnaryExpression() &&
        !path.isConditionalExpression()
      ) {
        return;
      }

      const evaluated = path.evaluate();
      if (!evaluated.confident) {
        return;
      }

      const literal = toLiteralNode(evaluated.value);
      if (!literal) {
        return;
      }

      path.replaceWith(literal);
      if (t.isStringLiteral(literal)) {
        context.noteString(literal.value);
      } else {
        context.noteChange();
      }
    },
    IfStatement(path: any) {
      const test = path.get("test").evaluate();
      if (!test.confident || typeof test.value !== "boolean") {
        return;
      }

      if (test.value) {
        if (t.isBlockStatement(path.node.consequent)) {
          path.replaceWithMultiple(path.node.consequent.body);
        } else {
          path.replaceWith(path.node.consequent);
        }
      } else if (path.node.alternate) {
        if (t.isBlockStatement(path.node.alternate)) {
          path.replaceWithMultiple(path.node.alternate.body);
        } else {
          path.replaceWith(path.node.alternate);
        }
      } else {
        path.remove();
      }

      context.noteChange();
    }
  });
}
