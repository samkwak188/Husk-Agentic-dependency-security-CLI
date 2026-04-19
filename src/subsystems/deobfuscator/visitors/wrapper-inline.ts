import traverseImport from "@babel/traverse";
import * as t from "@babel/types";

import type { DeobfuscationContext } from "../pipeline.js";

const traverse = (traverseImport as any).default ?? traverseImport;

interface InlineableWrapper {
  name: string;
  params: string[];
  expression: t.Expression;
}

function buildExpressionWithArgs(expression: t.Expression, params: string[], args: t.Expression[]): t.Expression {
  const file = t.file(t.program([t.expressionStatement(t.cloneNode(expression, true))]));
  const replacements = new Map<string, t.Expression>();

  params.forEach((param, index) => {
    const arg = args[index];
    if (arg) {
      replacements.set(param, t.cloneNode(arg, true));
    }
  });

  traverse(file, {
    Identifier(path: any) {
      if (!replacements.has(path.node.name)) {
        return;
      }

      if (!path.isReferencedIdentifier()) {
        return;
      }

      path.replaceWith(t.cloneNode(replacements.get(path.node.name)!, true));
    }
  });

  const statement = file.program.body[0];
  if (!statement || !t.isExpressionStatement(statement)) {
    return t.cloneNode(expression, true);
  }

  return statement.expression;
}

function collectWrappers(ast: t.File): Map<string, InlineableWrapper> {
  const wrappers = new Map<string, InlineableWrapper>();

  traverse(ast, {
    FunctionDeclaration(path: any) {
      const wrapper = extractInlineable(path.node);
      if (wrapper) {
        wrappers.set(wrapper.name, wrapper);
      }
    },
    VariableDeclarator(path: any) {
      if (!t.isIdentifier(path.node.id)) {
        return;
      }

      const init = path.node.init;
      if (!(t.isArrowFunctionExpression(init) || t.isFunctionExpression(init))) {
        return;
      }

      const wrapper = extractInlineable({
        ...init,
        id: path.node.id,
        type: "FunctionDeclaration"
      } as t.FunctionDeclaration);

      if (wrapper) {
        wrappers.set(wrapper.name, wrapper);
      }
    }
  });

  return wrappers;
}

function extractInlineable(node: t.FunctionDeclaration): InlineableWrapper | null {
  if (!node.id) {
    return null;
  }

  if (!node.params.every((param) => t.isIdentifier(param))) {
    return null;
  }

  if (!t.isBlockStatement(node.body) || node.body.body.length !== 1) {
    return null;
  }

  const statement = node.body.body[0];
  if (!t.isReturnStatement(statement) || !statement.argument || !t.isExpression(statement.argument)) {
    return null;
  }

  return {
    name: node.id.name,
    params: node.params.map((param) => (param as t.Identifier).name),
    expression: statement.argument
  };
}

export function runWrapperInlineVisitor(ast: t.File, context: DeobfuscationContext): void {
  const wrappers = collectWrappers(ast);

  traverse(ast, {
    CallExpression(path: any) {
      if (!t.isIdentifier(path.node.callee)) {
        return;
      }

      const wrapper = wrappers.get(path.node.callee.name);
      if (!wrapper || path.node.arguments.some((arg: any) => !t.isExpression(arg))) {
        return;
      }

      const args = path.node.arguments as t.Expression[];
      const replacement = buildExpressionWithArgs(wrapper.expression, wrapper.params, args);
      path.replaceWith(replacement);
      context.noteInline();
    }
  });

  traverse(ast, {
    FunctionDeclaration(path: any) {
      if (!path.node.id) {
        return;
      }

      const binding = path.scope.getBinding(path.node.id.name);
      if (binding && binding.referencePaths.length === 0) {
        path.remove();
        context.noteChange();
      }
    },
    VariableDeclarator(path: any) {
      if (!t.isIdentifier(path.node.id)) {
        return;
      }

      const binding = path.scope.getBinding(path.node.id.name);
      if (binding && binding.referencePaths.length === 0) {
        path.remove();
        context.noteChange();
      }
    }
  });
}
