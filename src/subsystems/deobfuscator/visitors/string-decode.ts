import traverseImport from "@babel/traverse";
import * as t from "@babel/types";

import type { DeobfuscationContext } from "../pipeline.js";

const traverse = (traverseImport as any).default ?? traverseImport;

function decodeBase64(value: string): string | null {
  try {
    return Buffer.from(value, "base64").toString("utf8");
  } catch {
    return null;
  }
}

export function runStringDecodeVisitor(ast: t.File, context: DeobfuscationContext): void {
  traverse(ast, {
    StringLiteral(path: any) {
      const raw = path.node.extra?.raw ?? "";
      if (/\\x[0-9a-f]{2}|\\u00[0-9a-f]{2}/i.test(raw)) {
        path.replaceWith(t.stringLiteral(path.node.value));
        context.noteString(path.node.value);
      }
    },
    CallExpression(path: any) {
      const { node } = path;

      if (
        t.isMemberExpression(node.callee) &&
        t.isIdentifier(node.callee.object, { name: "String" }) &&
        t.isIdentifier(node.callee.property, { name: "fromCharCode" }) &&
        node.arguments.every((arg: any) => t.isNumericLiteral(arg))
      ) {
        const value = String.fromCharCode(...node.arguments.map((arg: any) => (arg as t.NumericLiteral).value));
        path.replaceWith(t.stringLiteral(value));
        context.noteString(value);
        return;
      }

      if (t.isIdentifier(node.callee, { name: "atob" }) && node.arguments.length === 1 && t.isStringLiteral(node.arguments[0])) {
        const decoded = decodeBase64(node.arguments[0].value);
        if (decoded !== null) {
          path.replaceWith(t.stringLiteral(decoded));
          context.noteString(decoded);
        }
        return;
      }

      if (
        t.isMemberExpression(node.callee) &&
        t.isCallExpression(node.callee.object) &&
        t.isMemberExpression(node.callee.object.callee) &&
        t.isIdentifier(node.callee.object.callee.object, { name: "Buffer" }) &&
        t.isIdentifier(node.callee.object.callee.property, { name: "from" }) &&
        node.callee.object.arguments.length >= 1 &&
        t.isStringLiteral(node.callee.object.arguments[0]) &&
        t.isIdentifier(node.callee.property, { name: "toString" })
      ) {
        const encodingArg = node.callee.object.arguments[1];
        const encoding = t.isStringLiteral(encodingArg) ? encodingArg.value : undefined;
        if (encoding === "base64") {
          const decoded = decodeBase64(node.callee.object.arguments[0].value);
          if (decoded !== null) {
            path.replaceWith(t.stringLiteral(decoded));
            context.noteString(decoded);
          }
        }
      }
    }
  });
}
