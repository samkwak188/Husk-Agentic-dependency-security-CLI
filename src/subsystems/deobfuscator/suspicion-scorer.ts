import { parse } from "@babel/parser";
import traverseImport from "@babel/traverse";
import * as t from "@babel/types";

const traverse = (traverseImport as any).default ?? traverseImport;

interface SuspicionSummary {
  sinks: Set<string>;
  urls: Set<string>;
  strings: Set<string>;
  dangerousSinkCount: number;
}

const PARSER_PLUGINS = [
  "jsx",
  "typescript",
  "classProperties",
  "dynamicImport",
  "topLevelAwait",
  "optionalChaining"
] as const;

function isRequireCall(node: t.Node, moduleName: string): boolean {
  return (
    t.isCallExpression(node) &&
    t.isIdentifier(node.callee, { name: "require" }) &&
    node.arguments.length === 1 &&
    t.isStringLiteral(node.arguments[0], { value: moduleName })
  );
}

/**
 * Hosts that are benign by construction — collecting them as "outbound URLs"
 * only generates noise. Most legitimate packages ship docs / repo / homepage
 * URLs in their source; flagging those as exfiltration destinations is what
 * caused webpack to be blocked on `https://github.com/webpack/webpack-cli`.
 *
 * We err on the side of explicit allowlisting (suffix match on the host)
 * rather than broad heuristics so a typosquat like `github.io.evil.com`
 * still gets flagged.
 */
const BENIGN_URL_HOST_SUFFIXES = [
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "github.io",
  "githubusercontent.com",
  "registry.npmjs.org",
  "npmjs.com",
  "nodejs.org",
  "pypi.org",
  "python.org",
  "developer.mozilla.org",
  "json-schema.org",
  "schemas.microsoft.com",
  "schema.org",
  "w3.org",
  "ietf.org",
  "rfc-editor.org",
  "spdx.org",
  "wikipedia.org",
  "opensource.org",
  "googleapis.com",
  "cloudflare.com",
  "jsdelivr.net",
  "unpkg.com"
];

function extractHost(url: string): string | null {
  const match = url.match(/^https?:\/\/([^\/?#:\s'"]+)/i);
  return match ? match[1].toLowerCase() : null;
}

function isBenignUrl(url: string): boolean {
  const host = extractHost(url);
  if (!host) return false;
  return BENIGN_URL_HOST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

/**
 * Names of methods that, if a URL is passed as an argument, indicate the URL
 * will actually be fetched / sent to. Strings appearing anywhere else (error
 * messages, comments-as-strings, JSDoc, package metadata) are documentation,
 * not sinks.
 */
const NETWORK_SINK_METHODS = new Set([
  "fetch",
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "head",
  "request",
  "axios",
  "open",
  "send",
  "createConnection",
  "connect"
]);

function calleeMethodName(node: t.CallExpression): string | null {
  if (t.isIdentifier(node.callee)) return node.callee.name;
  if (t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.property)) {
    return node.callee.property.name;
  }
  return null;
}

function isLikelyNetworkSinkCall(node: t.CallExpression): boolean {
  const name = calleeMethodName(node);
  return name !== null && NETWORK_SINK_METHODS.has(name);
}

function collectUrlFromArg(arg: t.Node, urls: Set<string>, strings: Set<string>): void {
  if (t.isStringLiteral(arg) && /https?:\/\//i.test(arg.value)) {
    if (!isBenignUrl(arg.value)) {
      urls.add(arg.value);
      strings.add(arg.value);
    }
  } else if (t.isTemplateLiteral(arg)) {
    for (const quasi of arg.quasis) {
      if (/https?:\/\//i.test(quasi.value.raw) && !isBenignUrl(quasi.value.raw)) {
        urls.add(quasi.value.raw);
        strings.add(quasi.value.raw);
      }
    }
  }
}

export function scoreSuspicion(source: string): SuspicionSummary {
  const sinks = new Set<string>();
  const urls = new Set<string>();
  const strings = new Set<string>();

  let ast;
  try {
    ast = parse(source, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      errorRecovery: true,
      plugins: [...PARSER_PLUGINS]
    });
  } catch {
    return { sinks, urls, strings, dangerousSinkCount: 0 };
  }

  traverse(ast, {
    CallExpression(path: any) {
      const { node } = path;

      for (const moduleName of ["child_process", "net", "http", "https", "fs", "dns"]) {
        if (isRequireCall(node, moduleName)) {
          sinks.add(`require:${moduleName}`);
        }
      }

      if (t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.property)) {
        const name = node.callee.property.name;
        if (["exec", "execSync", "spawn", "spawnSync", "request", "get", "writeFile", "appendFile", "resolve"].includes(name)) {
          sinks.add(name);
        }
      }

      // Only collect URLs that are actually being passed into a network sink.
      // A URL hardcoded in a comment, a doc string, or a package homepage
      // field is not a sink — flagging it caused webpack/eslint to be marked
      // SUSPICIOUS on legitimate github.com / docs URLs.
      if (isLikelyNetworkSinkCall(node)) {
        for (const arg of node.arguments) {
          collectUrlFromArg(arg, urls, strings);
        }
      }
    },
    ImportDeclaration(path: any) {
      const value = path.node.source.value;
      if (["child_process", "net", "http", "https", "fs", "dns"].includes(value)) {
        sinks.add(`import:${value}`);
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
        sinks.add(`env:${node.property.name}`);
      }
    },
    StringLiteral(path: any) {
      // Strings remain useful as a soft signal for credential/process
      // keywords, but we no longer treat free-floating URLs as outbound.
      const value = path.node.value;
      if (/(child_process|curl|wget|base64|token|github_token|npmrc|\.aws)/i.test(value)) {
        strings.add(value);
      }
    }
  });

  return {
    sinks,
    urls,
    strings,
    dangerousSinkCount: sinks.size + urls.size
  };
}

export function calculateSuspicionScore(source: string): number {
  const summary = scoreSuspicion(source);
  return Math.min(100, summary.sinks.size * 10 + summary.urls.size * 20 + summary.strings.size * 2);
}
