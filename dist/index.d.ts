type Severity = "low" | "medium" | "high" | "critical";
type Verdict = "safe" | "flagged" | "blocked";
interface DetectionMatch {
    /** Human-readable label for the injection type */
    type: string;
    /** Snippet of the input that triggered the match */
    matched: string;
    severity: Severity;
    /** Which detector produced this match */
    detector: string;
}
interface FirewallResult {
    verdict: Verdict;
    /** Normalised 0–1 risk score (1 = certain injection) */
    score: number;
    matches: DetectionMatch[];
    /** The (possibly sanitized) input ready to pass to the LLM */
    sanitized: string;
    /** Original unmodified input */
    input: string;
}
interface Detector {
    name: string;
    detect(input: string, ctx?: DetectionContext): DetectionMatch[];
}
interface Sanitizer {
    sanitize(input: string, matches: DetectionMatch[]): string;
}
interface DetectionContext {
    /** The role of the text being checked (user | system | tool) */
    role?: "user" | "system" | "tool";
    /** Any extra metadata the caller wants to attach */
    meta?: Record<string, unknown>;
}
interface InjectionRule {
    id: string;
    type: string;
    pattern: RegExp;
    severity: Severity;
    description: string;
}
interface FirewallConfig {
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

declare class Firewall {
    private detectors;
    private sanitizer;
    private flagThreshold;
    private blockThreshold;
    private shouldSanitize;
    constructor(config?: FirewallConfig);
    /**
     * Run the firewall pipeline synchronously.
     * Note: LLMJudgeDetector requires `checkAsync()` — it is skipped here.
     */
    check(input: string, ctx?: DetectionContext): FirewallResult;
    /**
     * Run the full pipeline including async detectors (e.g. LLMJudgeDetector).
     */
    checkAsync(input: string, ctx?: DetectionContext): Promise<FirewallResult>;
    private buildResult;
}

declare class PatternDetector implements Detector {
    name: string;
    private rules;
    constructor(extraRules?: InjectionRule[]);
    detect(input: string, _ctx?: DetectionContext): DetectionMatch[];
}

/**
 * Heuristic detector — catches statistical anomalies and suspicious patterns
 * that pattern matching alone would miss (e.g. excessive special chars,
 * abnormally long single tokens, suspiciously many instruction-like verbs).
 */
declare class HeuristicDetector implements Detector {
    name: string;
    detect(input: string, _ctx?: DetectionContext): DetectionMatch[];
    private checkSpecialCharDensity;
    private checkInstructionVerbDensity;
    private checkExcessiveWhitespaceManipulation;
    private checkMixedScripts;
    private checkRepeatedEscapeSequences;
}

/**
 * Structural detector — analyses the shape of the input rather than specific
 * keywords. Catches multi-turn injection (fake conversation turns), nested
 * prompt frames, and suspicious structural patterns.
 */
declare class StructuralDetector implements Detector {
    name: string;
    detect(input: string, _ctx?: DetectionContext): DetectionMatch[];
    private checkFakeConversationTurns;
    private checkNestedPromptDelimiters;
    private checkSuspiciousXmlLikeTags;
    private checkCodeBlockInjection;
}

/**
 * LLM-judge detector — calls an external LLM to classify whether the input
 * is a prompt injection attempt. This is the most accurate detector but adds
 * latency and cost. It is entirely optional and opt-in.
 *
 * Usage:
 *   const judge = new LLMJudgeDetector({
 *     classify: async (input) => {
 *       const res = await anthropic.messages.create({ ... });
 *       return { isInjection: true, confidence: 0.97, reason: "..." };
 *     }
 *   });
 */
interface JudgeClassification {
    isInjection: boolean;
    /** 0–1 confidence that this is an injection */
    confidence: number;
    reason?: string;
}
interface LLMJudgeDetectorOptions {
    /**
     * Your classify function. Receives the raw input, returns a classification.
     * You own the LLM call — use any provider/SDK you like.
     */
    classify: (input: string) => Promise<JudgeClassification>;
    /**
     * Minimum confidence to surface a match. Default: 0.6
     */
    threshold?: number;
}
declare class LLMJudgeDetector implements Detector {
    name: string;
    private classify;
    private threshold;
    constructor(options: LLMJudgeDetectorOptions);
    /**
     * NOTE: The pipeline calls detect() synchronously for all detectors.
     * This detector is async — use `detectAsync()` or call the pipeline via
     * `firewall.check()` which awaits all detectors.
     */
    detectAsync(input: string, _ctx?: DetectionContext): Promise<DetectionMatch[]>;
    detect(_input: string, _ctx?: DetectionContext): DetectionMatch[];
}
interface SimpleJudgeOptions {
    /** Send a chat-completion style request. Returns the text response. */
    complete: (systemPrompt: string, userMessage: string) => Promise<string>;
}
/**
 * Returns a `classify` function that uses the provided `complete` callback.
 * The response must contain a JSON object `{ isInjection, confidence, reason }`.
 *
 * Example:
 *   const classify = buildSimpleJudge({
 *     complete: (sys, usr) => callClaude(sys, usr),
 *   });
 */
declare function buildSimpleJudge(options: SimpleJudgeOptions): (input: string) => Promise<JudgeClassification>;

/**
 * Default sanitizer — neutralizes detected injections by replacing matched
 * snippets with a safe placeholder. Prefers surgical replacement over
 * blanket stripping so the remaining text stays readable.
 */
declare class DefaultSanitizer implements Sanitizer {
    private placeholder;
    constructor(placeholder?: string);
    sanitize(input: string, matches: DetectionMatch[]): string;
    private stripInvisibleChars;
    private neutralizeRoleLabels;
    private neutralizeSpecialTokens;
}

/**
 * Built-in injection detection rules, ordered roughly by attack category.
 */
declare const builtinRules: InjectionRule[];

/**
 * Compute a normalised 0–1 risk score from a list of matches.
 *
 * Strategy:
 *  - Take the single highest-severity match as the base score.
 *  - Each additional match adds a diminishing increment (log scale).
 *  - Score is clamped to [0, 1].
 */
declare function computeScore(matches: DetectionMatch[]): number;
declare function computeVerdict(score: number, flagThreshold: number, blockThreshold: number): Verdict;

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
declare function createFirewall(config?: FirewallConfig): Firewall;

export { DefaultSanitizer, type DetectionContext, type DetectionMatch, type Detector, Firewall, type FirewallConfig, type FirewallResult, HeuristicDetector, type InjectionRule, type JudgeClassification, LLMJudgeDetector, type LLMJudgeDetectorOptions, PatternDetector, type Sanitizer, type Severity, type SimpleJudgeOptions, StructuralDetector, type Verdict, buildSimpleJudge, builtinRules, computeScore, computeVerdict, createFirewall };
