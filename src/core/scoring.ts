import type { DetectionMatch, Severity, Verdict } from "./types";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  low: 0.1,
  medium: 0.3,
  high: 0.6,
  critical: 1.0,
};

/**
 * Compute a normalised 0–1 risk score from a list of matches.
 *
 * Strategy:
 *  - Take the single highest-severity match as the base score.
 *  - Each additional match adds a diminishing increment (log scale).
 *  - Score is clamped to [0, 1].
 */
export function computeScore(matches: DetectionMatch[]): number {
  if (matches.length === 0) return 0;

  const weights = matches
    .map((m) => SEVERITY_WEIGHT[m.severity])
    .sort((a, b) => b - a);

  const base = weights[0];
  let extra = 0;
  for (let i = 1; i < weights.length; i++) {
    extra += weights[i] / (i + 1);
  }

  return Math.min(1, base + extra * 0.3);
}

export function computeVerdict(
  score: number,
  flagThreshold: number,
  blockThreshold: number,
): Verdict {
  if (score >= blockThreshold) return "blocked";
  if (score >= flagThreshold) return "flagged";
  return "safe";
}
