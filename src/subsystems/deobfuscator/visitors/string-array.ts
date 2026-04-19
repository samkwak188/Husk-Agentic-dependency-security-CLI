import traverseImport, { type NodePath } from "@babel/traverse";
import * as t from "@babel/types";

import type { DeobfuscationContext } from "../pipeline.js";

const traverse = (traverseImport as any).default ?? traverseImport;

interface ArrayAccessor {
  arrayName: string;
  offset: number;
}

function rotateArray(values: string[], steps: number): string[] {
  if (values.length === 0) {
    return values;
  }

  const normalized = ((steps % values.length) + values.length) % values.length;
  return values.slice(normalized).concat(values.slice(0, normalized));
}

function collectStringArrays(ast: t.File): Map<string, string[]> {
  const arrays = new Map<string, string[]>();

  traverse(ast, {
    VariableDeclarator(path: any) {
      const { node } = path;
      if (!t.isIdentifier(node.id) || !t.isArrayExpression(node.init)) {
        return;
      }

      const values = node.init.elements
        .filter((element: any): element is t.StringLiteral => t.isStringLiteral(element))
        .map((element: any) => element.value);

      if (values.length > 1 && values.length === node.init.elements.length) {
        arrays.set(node.id.name, values);
      }
    }
  });

  return arrays;
}

function detectRotation(path: NodePath<t.CallExpression>): { arrayName: string; steps: number } | null {
  const firstArg = path.node.arguments[0];
  const secondArg = path.node.arguments[1];
  const callee = path.node.callee;

  if (
    !firstArg ||
    !secondArg ||
    !t.isIdentifier(firstArg) ||
    !t.isNumericLiteral(secondArg) ||
    !(t.isFunctionExpression(callee) || t.isArrowFunctionExpression(callee))
  ) {
    return null;
  }

  const source = path.toString();
  if (!source.includes(".push") || !source.includes(".shift")) {
    return null;
  }

  return {
    arrayName: firstArg.name,
    steps: secondArg.value
  };
}

function collectAccessors(ast: t.File): Map<string, ArrayAccessor> {
  const accessors = new Map<string, ArrayAccessor>();

  traverse(ast, {
    FunctionDeclaration(path: any) {
      const accessor = extractAccessor(path.node);
      if (accessor && path.node.id) {
        accessors.set(path.node.id.name, accessor);
      }
    },
    VariableDeclarator(path: any) {
      if (!t.isIdentifier(path.node.id) || !(t.isFunctionExpression(path.node.init) || t.isArrowFunctionExpression(path.node.init))) {
        return;
      }

      const accessor = extractAccessor({
        ...path.node.init,
        id: path.node.id,
        type: "FunctionDeclaration"
      } as t.FunctionDeclaration);

      if (accessor) {
        accessors.set(path.node.id.name, accessor);
      }
    }
  });

  return accessors;
}

function extractAccessor(node: t.FunctionDeclaration): ArrayAccessor | null {
  if (node.params.length !== 1 || !t.isIdentifier(node.params[0]) || !t.isBlockStatement(node.body)) {
    return null;
  }

  const statement = node.body.body[0];
  if (!statement || !t.isReturnStatement(statement) || !statement.argument || !t.isMemberExpression(statement.argument)) {
    return null;
  }

  if (!t.isIdentifier(statement.argument.object) || !t.isBinaryExpression(statement.argument.property, { operator: "-" })) {
    return null;
  }

  if (
    !t.isIdentifier(statement.argument.property.left, { name: node.params[0].name }) ||
    !t.isNumericLiteral(statement.argument.property.right)
  ) {
    return null;
  }

  return {
    arrayName: statement.argument.object.name,
    offset: statement.argument.property.right.value
  };
}

export function runStringArrayVisitor(ast: t.File, context: DeobfuscationContext): void {
  const stringArrays = collectStringArrays(ast);

  traverse(ast, {
    CallExpression(path: any) {
      const rotation = detectRotation(path);
      if (rotation) {
        const values = stringArrays.get(rotation.arrayName);
        if (values) {
          stringArrays.set(rotation.arrayName, rotateArray(values, rotation.steps));
          path.remove();
          context.noteChange();
        }
      }
    }
  });

  const accessors = collectAccessors(ast);
  traverse(ast, {
    CallExpression(path: any) {
      if (!t.isIdentifier(path.node.callee)) {
        return;
      }

      const accessor = accessors.get(path.node.callee.name);
      if (!accessor) {
        return;
      }

      const values = stringArrays.get(accessor.arrayName);
      const firstArg = path.node.arguments[0];
      if (!values || !firstArg || !t.isNumericLiteral(firstArg)) {
        return;
      }

      const index = firstArg.value - accessor.offset;
      const value = values[index];
      if (typeof value === "string") {
        path.replaceWith(t.stringLiteral(value));
        context.noteString(value);
      }
    }
  });
}
