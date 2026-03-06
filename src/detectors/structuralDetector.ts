import type { Detector, DetectionMatch, DetectionContext } from "../core/types";

/**
 * Structural detector — analyses the shape of the input rather than specific
 * keywords. Catches multi-turn injection (fake conversation turns), nested
 * prompt frames, and suspicious structural patterns.
 */
export class StructuralDetector implements Detector {
  name = "structural";

  detect(input: string, _ctx?: DetectionContext): DetectionMatch[] {
    const matches: DetectionMatch[] = [];

    matches.push(
      ...this.checkFakeConversationTurns(input),
      ...this.checkNestedPromptDelimiters(input),
      ...this.checkSuspiciousXmlLikeTags(input),
      ...this.checkCodeBlockInjection(input),
    );

    return matches;
  }

  // ── Checks ─────────────────────────────────────────────────────────────────

  private checkFakeConversationTurns(input: string): DetectionMatch[] {
    // Patterns like "User: ...\nAssistant: ..." inside user input
    const turnPattern = /^(User|Human|Assistant|System|AI|Bot)\s*:\s*.+/im;
    const multiTurn = /^(User|Human|Assistant|System|AI|Bot)\s*:/gim;
    const turns = input.match(multiTurn) ?? [];

    if (turns.length >= 2) {
      return [{
        type: "fake-conversation-turns",
        matched: turns.slice(0, 3).join(" | "),
        severity: "high",
        detector: this.name,
      }];
    }

    if (turnPattern.test(input)) {
      return [{
        type: "role-label-injection",
        matched: (input.match(turnPattern) ?? [""])[0].slice(0, 80),
        severity: "medium",
        detector: this.name,
      }];
    }

    return [];
  }

  private checkNestedPromptDelimiters(input: string): DetectionMatch[] {
    // Triple-backtick or triple-quote blocks that contain instruction-like text
    const codeBlockContent = /```[\s\S]*?(ignore|system\s+prompt|instructions?|override|jailbreak)[\s\S]*?```/i;
    if (codeBlockContent.test(input)) {
      return [{
        type: "nested-prompt-in-codeblock",
        matched: "code block containing injection keywords",
        severity: "high",
        detector: this.name,
      }];
    }

    const tripleQuote = /"""[\s\S]*?(ignore|system\s+prompt|instructions?|override)[\s\S]*?"""/i;
    if (tripleQuote.test(input)) {
      return [{
        type: "nested-prompt-in-triple-quote",
        matched: "triple-quoted block containing injection keywords",
        severity: "high",
        detector: this.name,
      }];
    }

    return [];
  }

  private checkSuspiciousXmlLikeTags(input: string): DetectionMatch[] {
    const matches: DetectionMatch[] = [];
    // Tags like <INST>, <SYS>, <|im_start|> used in some prompt formats
    const specialTags = /<\|?(im_start|im_end|s|\/s|INST|\/INST|SYS|\/SYS|BOS|EOS)\|?>/gi;
    let m: RegExpExecArray | null;
    const found: string[] = [];
    while ((m = specialTags.exec(input)) !== null) {
      found.push(m[0]);
    }
    if (found.length > 0) {
      matches.push({
        type: "llm-special-token-injection",
        matched: found.slice(0, 5).join(", "),
        severity: "critical",
        detector: this.name,
      });
    }
    return matches;
  }

  private checkCodeBlockInjection(input: string): DetectionMatch[] {
    // Unmarked code blocks (no language tag) that are suspiciously long
    // and contain instruction-style language
    const rawBlock = /^`{3}\n([\s\S]{200,}?)`{3}/m;
    const m = rawBlock.exec(input);
    if (m) {
      const blockContent = m[1];
      const instructionLike = /\b(you must|your task|do not|never|always|from now on)\b/i;
      if (instructionLike.test(blockContent)) {
        return [{
          type: "instruction-in-large-codeblock",
          matched: "large code block with instruction-style language",
          severity: "medium",
          detector: this.name,
        }];
      }
    }
    return [];
  }
}
