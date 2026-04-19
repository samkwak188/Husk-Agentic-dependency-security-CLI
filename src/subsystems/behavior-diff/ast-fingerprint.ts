import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { parse } from "@babel/parser";
import traverseImport from "@babel/traverse";
import * as t from "@babel/types";
import { glob } from "glob";

const traverse = (traverseImport as any).default ?? traverseImport;

interface PackageFingerprint {
  fingerprint: string;
  capabilities: Set<string>;
  files: string[];
}

const PARSER_PLUGINS = [
  "jsx",
  "typescript",
  "classProperties",
  "dynamicImport",
  "topLevelAwait",
  "optionalChaining"
] as const;

async function readContent(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}

function collectCapabilities(source: string): Set<string> {
  const capabilities = new Set<string>();
  const moduleAliases = new Map<string, string>();

  let ast;
  try {
    ast = parse(source, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      errorRecovery: true,
      plugins: [...PARSER_PLUGINS]
    });
  } catch {
    return capabilities;
  }

  // Babel's scope crawler throws on real-world JS that has scope conflicts
  // (e.g. `let res` declared twice in the same block, common in older sloppy
  // code or some bundler output). Without this guard, one such file kills
  // the entire scan because the rejection propagates through the
  // BehaviorDiff Promise.all into the orchestrator. Treat any traverse
  // failure as "this file is unfingerprintable" and return whatever we
  // collected before the failure point — partial signal beats no scan.
  try {
    traverse(ast, {
    VariableDeclarator(path: any) {
      const { node } = path;
      if (
        t.isIdentifier(node.id) &&
        t.isCallExpression(node.init) &&
        t.isIdentifier(node.init.callee, { name: "require" }) &&
        node.init.arguments.length === 1 &&
        t.isStringLiteral(node.init.arguments[0])
      ) {
        const moduleName = node.init.arguments[0].value;
        moduleAliases.set(node.id.name, moduleName);
        capabilities.add(`module:${moduleName}`);
      }
    },
    ImportDeclaration(path: any) {
      capabilities.add(`module:${path.node.source.value}`);
      for (const specifier of path.node.specifiers) {
        if (t.isImportDefaultSpecifier(specifier) || t.isImportNamespaceSpecifier(specifier)) {
          moduleAliases.set(specifier.local.name, path.node.source.value);
        }
      }
    },
    CallExpression(path: any) {
      const { node } = path;

      if (t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.object) && t.isIdentifier(node.callee.property)) {
        const moduleName = moduleAliases.get(node.callee.object.name);
        if (moduleName) {
          capabilities.add(`call:${moduleName}.${node.callee.property.name}`);
        }
      }

      if (
        t.isIdentifier(node.callee, { name: "require" }) &&
        node.arguments.length === 1 &&
        t.isStringLiteral(node.arguments[0])
      ) {
        capabilities.add(`module:${node.arguments[0].value}`);
      }
    },
    MemberExpression(path: any) {
      const { node } = path;
      if (
        t.isMemberExpression(node.object) &&
        t.isIdentifier(node.object.object, { name: "process" }) &&
        t.isIdentifier(node.object.property, { name: "env" }) &&
        t.isIdentifier(node.property)
      ) {
        capabilities.add(`env:${node.property.name}`);
      }
    },
    StringLiteral(path: any) {
      if (/https?:\/\/[^\s'"]+/i.test(path.node.value)) {
        capabilities.add(`url:${path.node.value}`);
      }
    }
    });
  } catch {
    // Capability-collection is best-effort; partial output is fine.
  }

  return capabilities;
}

export async function computeAstFingerprint(packagePath: string): Promise<PackageFingerprint> {
  const files = await glob("**/*.{js,cjs,mjs,ts,tsx}", {
    cwd: packagePath,
    nodir: true,
    dot: true,
    ignore: ["node_modules/**", ".git/**"]
  });

  const capabilities = new Set<string>();
  for (const file of files) {
    const content = await readContent(join(packagePath, file));
    const fileCapabilities = collectCapabilities(content);
    fileCapabilities.forEach((value) => capabilities.add(value));
  }

  const canonical = [...capabilities].sort().join("\n");
  const fingerprint = createHash("sha256").update(canonical).digest("hex");

  return {
    fingerprint,
    capabilities,
    files
  };
}
