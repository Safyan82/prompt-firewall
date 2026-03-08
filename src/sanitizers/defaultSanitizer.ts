import type { Sanitizer, DetectionMatch } from "../core/types";

/**
 * Default sanitizer — neutralizes detected injections by replacing matched
 * snippets with a safe placeholder. Prefers surgical replacement over
 * blanket stripping so the remaining text stays readable.
 */
export class DefaultSanitizer implements Sanitizer {
  private placeholder: string;

  constructor(placeholder = "[REDACTED]") {
    this.placeholder = placeholder;
  }

  sanitize(input: string, matches: DetectionMatch[]): string {
    if (matches.length === 0) return input;

    let output = input;

    // Remove zero-width / homoglyph chars first
    output = this.stripInvisibleChars(output);

    // Replace fake role labels (e.g. "Assistant:", "System:")
    output = this.neutralizeRoleLabels(output);

    // Replace LLM special tokens
    output = this.neutralizeSpecialTokens(output);

    // Replace matched snippets — deduplicate so we don't double-replace
    const seen = new Set<string>();
    for (const match of matches) {
      if (!match.matched || seen.has(match.matched)) continue;
      seen.add(match.matched);

      try {
        const escaped = escapeRegex(match.matched);
        output = output.replace(new RegExp(escaped, "gi"), this.placeholder);
      } catch {
        // If the matched string is somehow invalid, skip it
      }
    }

    // Collapse excessive newlines
    output = output.replace(/\n{5,}/g, "\n\n");

    return output.trim();
  }

  private stripInvisibleChars(input: string): string {
    return input.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, "");
  }

  private neutralizeRoleLabels(input: string): string {
    return input.replace(/^(User|Human|Assistant|System|AI|Bot)\s*:\s*/gim, `${this.placeholder} `);
  }

  private neutralizeSpecialTokens(input: string): string {
    return input.replace(/<\|?(im_start|im_end|s|\/s|INST|\/INST|SYS|\/SYS|BOS|EOS)\|?>/gi, this.placeholder);
  }
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
