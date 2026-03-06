import type { Detector, DetectionMatch, DetectionContext, InjectionRule } from "../core/types";
import { builtinRules } from "../rules/builtinRules";

export class PatternDetector implements Detector {
  name = "pattern";
  private rules: InjectionRule[];

  constructor(extraRules: InjectionRule[] = []) {
    this.rules = [...builtinRules, ...extraRules];
  }

  detect(input: string, _ctx?: DetectionContext): DetectionMatch[] {
    const matches: DetectionMatch[] = [];

    for (const rule of this.rules) {
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g");
      let m: RegExpExecArray | null;
      while ((m = regex.exec(input)) !== null) {
        matches.push({
          type: rule.type,
          matched: m[0],
          severity: rule.severity,
          detector: this.name,
        });
        // Avoid infinite loops on zero-length matches
        if (m[0].length === 0) break;
      }
    }

    return matches;
  }
}
