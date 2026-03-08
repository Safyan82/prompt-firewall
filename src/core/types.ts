// ─── Severity ────────────────────────────────────────────────────────────────

export type Severity = "low" | "medium" | "high" | "critical";

// ─── Firewall verdict ────────────────────────────────────────────────────────

export type Verdict = "safe" | "flagged" | "blocked";

// ─── A single match found by a detector ──────────────────────────────────────

export interface DetectionMatch {
  /** Human-readable label for the injection type */
  type: string;
  /** Snippet of the input that triggered the match */
  matched: string;
  severity: Severity;
  /** Which detector produced this match */
  detector: string;
}

// ─── Result returned by the firewall ─────────────────────────────────────────

export interface FirewallResult {
  verdict: Verdict;
  /** Normalised 0–1 risk score (1 = certain injection) */
  score: number;
  matches: DetectionMatch[];
  /** The (possibly sanitized) input ready to pass to the LLM */
  sanitized: string;
  /** Original unmodified input */
  input: string;
}

// ─── Detector interface ───────────────────────────────────────────────────────

export interface Detector {
  name: string;
  detect(input: string, ctx?: DetectionContext): DetectionMatch[];
}

// ─── Sanitizer interface ──────────────────────────────────────────────────────

export interface Sanitizer {
  sanitize(input: string, matches: DetectionMatch[]): string;
}

// ─── Optional context passed through the pipeline ────────────────────────────

export interface DetectionContext {
  /** The role of the text being checked (user | system | tool) */
  role?: "user" | "system" | "tool";
  /** Any extra metadata the caller wants to attach */
  meta?: Record<string, unknown>;
}

// ─── Rule used by the pattern detector ───────────────────────────────────────

export interface InjectionRule {
  id: string;
  type: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
}

// ─── Firewall config ──────────────────────────────────────────────────────────

export interface FirewallConfig {
  /**
   * Score threshold above which the verdict becomes "flagged".
   * Default: 0.4
   */
  flagThreshold?: number;
  /**
   * Score threshold above which the verdict becomes "blocked".
   * Default: 0.7
   */
  blockThreshold?: number;
  /**
   * Whether to run the sanitizer and return a cleaned input.
   * Default: true
   */
  sanitize?: boolean;
  /**
   * Detectors to include in the pipeline.
   * Defaults to all built-in detectors.
   */
  detectors?: Detector[];
  /**
   * Custom rules appended to the pattern detector.
   */
  customRules?: InjectionRule[];
}
