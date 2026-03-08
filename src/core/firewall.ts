import type {
  FirewallConfig,
  FirewallResult,
  DetectionContext,
  Detector,
  DetectionMatch,
} from "./types";
import { PatternDetector } from "../detectors/patternDetector";
import { HeuristicDetector } from "../detectors/heuristicDetector";
import { StructuralDetector } from "../detectors/structuralDetector";
import { LLMJudgeDetector } from "../detectors/llmJudgeDetector";
import { DefaultSanitizer } from "../sanitizers/defaultSanitizer";
import { computeScore, computeVerdict } from "./scoring";

const DEFAULT_FLAG_THRESHOLD = 0.4;
const DEFAULT_BLOCK_THRESHOLD = 0.7;

export class Firewall {
  private detectors: Detector[];
  private sanitizer: DefaultSanitizer;
  private flagThreshold: number;
  private blockThreshold: number;
  private shouldSanitize: boolean;

  constructor(config: FirewallConfig = {}) {
    this.flagThreshold = config.flagThreshold ?? DEFAULT_FLAG_THRESHOLD;
    this.blockThreshold = config.blockThreshold ?? DEFAULT_BLOCK_THRESHOLD;
    this.shouldSanitize = config.sanitize ?? true;
    this.sanitizer = new DefaultSanitizer();

    if (config.detectors) {
      this.detectors = config.detectors;
    } else {
      this.detectors = [
        new PatternDetector(config.customRules),
        new HeuristicDetector(),
        new StructuralDetector(),
      ];
    }
  }

  /**
   * Run the firewall pipeline synchronously.
   * Note: LLMJudgeDetector requires `checkAsync()` — it is skipped here.
   */
  check(input: string, ctx?: DetectionContext): FirewallResult {
    const matches: DetectionMatch[] = [];

    for (const detector of this.detectors) {
      if (detector instanceof LLMJudgeDetector) continue; // requires async
      matches.push(...detector.detect(input, ctx));
    }

    return this.buildResult(input, matches);
  }

  /**
   * Run the full pipeline including async detectors (e.g. LLMJudgeDetector).
   */
  async checkAsync(input: string, ctx?: DetectionContext): Promise<FirewallResult> {
    const matchArrays = await Promise.all(
      this.detectors.map(async (detector) => {
        if (detector instanceof LLMJudgeDetector) {
          return detector.detectAsync(input, ctx);
        }
        return detector.detect(input, ctx);
      }),
    );

    const matches = matchArrays.flat();
    return this.buildResult(input, matches);
  }

  private buildResult(input: string, matches: DetectionMatch[]): FirewallResult {
    const score = computeScore(matches);
    const verdict = computeVerdict(score, this.flagThreshold, this.blockThreshold);
    const sanitized = this.shouldSanitize
      ? this.sanitizer.sanitize(input, matches)
      : input;

    return { verdict, score, matches, sanitized, input };
  }
}
