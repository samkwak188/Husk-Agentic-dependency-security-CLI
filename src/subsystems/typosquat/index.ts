import leven from "leven";

import type { TyposquatResult } from "../../core/types.js";
import { keyboardDistance } from "./keyboard-distance.js";
import { POPULAR_PACKAGES } from "./popular-packages.js";

function splitScopedName(name: string): { scope?: string; pkg: string } {
  if (!name.startsWith("@")) {
    return { pkg: name };
  }

  const [scope, pkg] = name.split("/");
  return {
    scope,
    pkg: pkg ?? ""
  };
}

function normalizeName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[@/_-]/g, "")
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/rn/g, "m");
}

export class TyposquatDetector {
  constructor(private readonly popularPackages = POPULAR_PACKAGES) {}

  check(name: string): TyposquatResult | null {
    if (this.popularPackages.includes(name)) {
      return null;
    }

    const normalized = normalizeName(name);
    let best: TyposquatResult | null = null;

    for (const candidate of this.popularPackages) {
      if (candidate === name) {
        continue;
      }

      const normalizedCandidate = normalizeName(candidate);
      const distance = leven(normalized, normalizedCandidate);
      const keyboardScore = keyboardDistance(normalized, normalizedCandidate);
      const reasons: string[] = [];

      if (distance <= 2) {
        reasons.push(`Levenshtein distance ${distance} to ${candidate}`);
      }

      if (keyboardScore <= 2 && normalized.length === normalizedCandidate.length) {
        reasons.push(`Keyboard-adjacent substitution pattern vs ${candidate}`);
      }

      const source = splitScopedName(name);
      const target = splitScopedName(candidate);
      if (source.pkg === target.pkg && source.scope && target.scope && source.scope !== target.scope) {
        reasons.push(`Scope squatting pattern: ${source.scope} vs ${target.scope}`);
      }

      if (!reasons.length) {
        continue;
      }

      const confidence = Math.max(0.3, 1 - (distance * 0.2 + keyboardScore * 0.1));
      const result: TyposquatResult = {
        target: candidate,
        distance,
        confidence: Number(confidence.toFixed(2)),
        reasons
      };

      if (!best || result.confidence > best.confidence) {
        best = result;
      }
    }

    return best;
  }
}
