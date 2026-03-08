// ─── Public API ───────────────────────────────────────────────────────────────

export { Firewall } from "./core/firewall";

// Types
export type {
  FirewallConfig,
  FirewallResult,
  DetectionMatch,
  DetectionContext,
  Detector,
  Sanitizer,
  InjectionRule,
  Verdict,
  Severity,
} from "./core/types";

// Detectors (for custom pipelines)
export { PatternDetector } from "./detectors/patternDetector";
export { HeuristicDetector } from "./detectors/heuristicDetector";
export { StructuralDetector } from "./detectors/structuralDetector";
export {
  LLMJudgeDetector,
  buildSimpleJudge,
} from "./detectors/llmJudgeDetector";
export type {
  LLMJudgeDetectorOptions,
  JudgeClassification,
  SimpleJudgeOptions,
} from "./detectors/llmJudgeDetector";

// Sanitizer
export { DefaultSanitizer } from "./sanitizers/defaultSanitizer";

// Built-in rules (for extending)
export { builtinRules } from "./rules/builtinRules";

// Scoring utilities
export { computeScore, computeVerdict } from "./core/scoring";

// ─── Convenience factory ──────────────────────────────────────────────────────

import { Firewall } from "./core/firewall";
import type { FirewallConfig } from "./core/types";

/**
 * Create a Firewall instance with optional config.
 *
 * @example
 * import { createFirewall } from "prompt-firewall";
 *
 * const firewall = createFirewall();
 * const result = firewall.check(userInput);
 * if (result.verdict === "blocked") throw new Error("Injection detected");
 */
export function createFirewall(config?: FirewallConfig): Firewall {
  return new Firewall(config);
}
