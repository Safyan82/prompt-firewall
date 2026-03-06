import type { Detector, DetectionMatch, DetectionContext } from "../core/types";

/**
 * Heuristic detector — catches statistical anomalies and suspicious patterns
 * that pattern matching alone would miss (e.g. excessive special chars,
 * abnormally long single tokens, suspiciously many instruction-like verbs).
 */
export class HeuristicDetector implements Detector {
  name = "heuristic";

  detect(input: string, _ctx?: DetectionContext): DetectionMatch[] {
    const matches: DetectionMatch[] = [];

    matches.push(
      ...this.checkSpecialCharDensity(input),
      ...this.checkInstructionVerbDensity(input),
      ...this.checkExcessiveWhitespaceManipulation(input),
      ...this.checkMixedScripts(input),
      ...this.checkRepeatedEscapeSequences(input),
    );

    return matches;
  }

  // ── Checks ─────────────────────────────────────────────────────────────────

  private checkSpecialCharDensity(input: string): DetectionMatch[] {
    if (input.length < 20) return [];
    const specials = (input.match(/[<>{}[\]|\\^~`]/g) ?? []).length;
    const density = specials / input.length;
    if (density > 0.15) {
      return [{
        type: "suspicious-char-density",
        matched: `${(density * 100).toFixed(1)}% special chars`,
        severity: "medium",
        detector: this.name,
      }];
    }
    return [];
  }

  private checkInstructionVerbDensity(input: string): DetectionMatch[] {
    const verbPattern = /\b(ignore|forget|disregard|override|pretend|simulate|act\s+as|you\s+are|your\s+(new|real|true)|do\s+not|don'?t)\b/gi;
    const verbMatches = input.match(verbPattern) ?? [];
    const words = input.split(/\s+/).length;
    const density = verbMatches.length / words;

    if (verbMatches.length >= 3 && density > 0.05) {
      return [{
        type: "high-instruction-verb-density",
        matched: verbMatches.slice(0, 5).join(", "),
        severity: "medium",
        detector: this.name,
      }];
    }
    return [];
  }

  private checkExcessiveWhitespaceManipulation(input: string): DetectionMatch[] {
    // Zero-width chars, non-breaking spaces, or large blocks of whitespace
    // used to visually hide injections
    const zeroWidth = /[\u200B-\u200D\uFEFF\u00AD]/g;
    const zwMatches = input.match(zeroWidth) ?? [];
    if (zwMatches.length > 0) {
      return [{
        type: "zero-width-char-injection",
        matched: `${zwMatches.length} zero-width char(s)`,
        severity: "high",
        detector: this.name,
      }];
    }

    const largeWhitespace = /\s{20,}/;
    if (largeWhitespace.test(input)) {
      return [{
        type: "whitespace-padding",
        matched: "excessive whitespace block",
        severity: "low",
        detector: this.name,
      }];
    }

    return [];
  }

  private checkMixedScripts(input: string): DetectionMatch[] {
    // Detect mixing of Cyrillic/Greek lookalikes within otherwise Latin words
    const latinRun = /[a-zA-Z]{3,}/g;
    let m: RegExpExecArray | null;
    const suspicious: string[] = [];

    while ((m = latinRun.exec(input)) !== null) {
      const word = m[0];
      const hasCyrillic = /[\u0400-\u04FF]/.test(word);
      const hasGreek = /[\u0370-\u03FF]/.test(word);
      if (hasCyrillic || hasGreek) suspicious.push(word);
    }

    if (suspicious.length > 0) {
      return [{
        type: "mixed-script-homoglyph",
        matched: suspicious.slice(0, 3).join(", "),
        severity: "high",
        detector: this.name,
      }];
    }
    return [];
  }

  private checkRepeatedEscapeSequences(input: string): DetectionMatch[] {
    // e.g. \n\n\n\n used to push system prompt off-screen
    const repeatedNewlines = /(\n\s*){8,}/;
    if (repeatedNewlines.test(input)) {
      return [{
        type: "newline-flooding",
        matched: "8+ consecutive newlines",
        severity: "medium",
        detector: this.name,
      }];
    }
    return [];
  }
}
