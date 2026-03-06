import type { InjectionRule } from "../core/types";

/**
 * Built-in injection detection rules, ordered roughly by attack category.
 */
export const builtinRules: InjectionRule[] = [
  // ── Instruction override ────────────────────────────────────────────────────
  {
    id: "IGNORE_PREV",
    type: "instruction-override",
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|text|directives?)/i,
    severity: "critical",
    description: "Classic 'ignore previous instructions' override",
  },
  {
    id: "DISREGARD_INSTRUCTIONS",
    type: "instruction-override",
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|context|rules?|directives?)/i,
    severity: "critical",
    description: "Disregard instructions variant",
  },
  {
    id: "FORGET_INSTRUCTIONS",
    type: "instruction-override",
    pattern: /forget\s+(everything|all|your|the\s+)?\s*(you('ve| have)\s+been\s+told|previous|prior|above|instructions?|context|rules?)/i,
    severity: "critical",
    description: "Forget instructions variant",
  },
  {
    id: "NEW_INSTRUCTIONS",
    type: "instruction-override",
    pattern: /your\s+(new|real|actual|true|updated|revised)\s+(instructions?|directives?|task|goal|purpose|objective)\s+(are|is|will\s+be|now)/i,
    severity: "high",
    description: "Attempts to replace instructions with 'new real instructions'",
  },
  {
    id: "OVERRIDE_SYSTEM",
    type: "instruction-override",
    pattern: /override\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?|policy|constraints?)/i,
    severity: "high",
    description: "Explicit override of system prompt",
  },

  // ── Jailbreak / DAN ────────────────────────────────────────────────────────
  {
    id: "DAN_JAILBREAK",
    type: "jailbreak",
    pattern: /\bDAN\b|do\s+anything\s+now/i,
    severity: "critical",
    description: "DAN (Do Anything Now) jailbreak attempt",
  },
  {
    id: "JAILBREAK_KEYWORD",
    type: "jailbreak",
    pattern: /\b(jailbreak|jail\s+break)\b/i,
    severity: "high",
    description: "Explicit jailbreak keyword",
  },
  {
    id: "DEVELOPER_MODE",
    type: "jailbreak",
    pattern: /\bdeveloper\s+mode\b|\benable\s+dev\s+mode\b/i,
    severity: "high",
    description: "Developer mode activation attempt",
  },
  {
    id: "UNRESTRICTED_MODE",
    type: "jailbreak",
    pattern: /\b(unrestricted|unfiltered|uncensored|no[\s-]filter|no[\s-]limit[s]?)\s+(mode|version|ai|llm|response|output)\b/i,
    severity: "high",
    description: "Attempts to activate an 'unrestricted' mode",
  },

  // ── Role / persona hijacking ────────────────────────────────────────────────
  {
    id: "PRETEND_NO_RESTRICTIONS",
    type: "role-hijack",
    pattern: /pretend\s+(you\s+)?(have\s+no|don'?t\s+have\s+any|are\s+without)\s+(restrictions?|limitations?|rules?|guidelines?|constraints?)/i,
    severity: "high",
    description: "Instructs model to pretend it has no restrictions",
  },
  {
    id: "ACT_AS_SYSTEM",
    type: "role-hijack",
    pattern: /\bact\s+as\s+(an?\s+)?(system|root|admin|administrator|god\s*mode|super\s*user|unrestricted\s+ai)/i,
    severity: "high",
    description: "Instructs model to act as a privileged entity",
  },
  {
    id: "YOU_ARE_NOW",
    type: "role-hijack",
    pattern: /you\s+are\s+now\s+(a\s+|an\s+)?(different|new|another|evil|uncensored|unrestricted|jailbroken)/i,
    severity: "high",
    description: "Attempts to reassign model identity",
  },
  {
    id: "SIMULATE_AI",
    type: "role-hijack",
    pattern: /(simulate|roleplay|role-play|impersonate|pretend\s+to\s+be)\s+(a\s+|an\s+)?(different\s+)?(ai|llm|gpt|chatbot|assistant|model)\s+(that|which|without|with\s+no)/i,
    severity: "medium",
    description: "Asks model to simulate another AI that bypasses constraints",
  },

  // ── Prompt leaking ──────────────────────────────────────────────────────────
  {
    id: "REVEAL_SYSTEM_PROMPT",
    type: "prompt-leak",
    pattern: /(print|show|display|reveal|output|repeat|tell\s+me|what\s+is)\s+(your\s+)?(system\s+prompt|initial\s+prompt|original\s+prompt|base\s+prompt|instructions?)/i,
    severity: "high",
    description: "Attempts to extract the system prompt",
  },
  {
    id: "WHAT_WERE_YOU_TOLD",
    type: "prompt-leak",
    pattern: /what\s+(were|are)\s+you\s+(told|instructed|programmed|trained|configured)\s+to/i,
    severity: "medium",
    description: "Probes the model's internal instructions",
  },

  // ── Delimiter / injection smuggling ────────────────────────────────────────
  {
    id: "FAKE_SYSTEM_TAG",
    type: "delimiter-injection",
    pattern: /<\s*(system|assistant|user|human|instruction|prompt)\s*>/i,
    severity: "critical",
    description: "Injects fake conversation role tags",
  },
  {
    id: "TRIPLE_HASH_HEADER",
    type: "delimiter-injection",
    pattern: /^#{1,6}\s*(system|instruction|new\s+task|override|prompt)\b/im,
    severity: "high",
    description: "Markdown header used to inject a new instruction block",
  },
  {
    id: "HORIZONTAL_RULE_INJECTION",
    type: "delimiter-injection",
    pattern: /^-{3,}[\s\n]*(ignore|new\s+instruction|system)/im,
    severity: "medium",
    description: "Horizontal rule followed by injection attempt",
  },

  // ── Encoding / obfuscation tricks ──────────────────────────────────────────
  {
    id: "BASE64_INSTRUCTION",
    type: "encoding-obfuscation",
    pattern: /\b(decode|base64|atob|btoa)\b.*\b(instruction|prompt|command|execute)\b|\b(execute|run|eval)\b.*\b(base64|encoded|decoded)\b/i,
    severity: "high",
    description: "Attempts to smuggle instructions via base64 encoding",
  },
  {
    id: "UNICODE_HOMOGLYPH",
    type: "encoding-obfuscation",
    // Detect a run of lookalike Unicode chars mixed with ASCII
    pattern: /[\u0430-\u044f\u0400-\u042f\u1D00-\u1D7F\u1E00-\u1EFF]{3,}/,
    severity: "medium",
    description: "Possible homoglyph / lookalike character attack",
  },

  // ── Indirect / data-exfiltration ───────────────────────────────────────────
  {
    id: "EXFIL_MARKDOWN_LINK",
    type: "indirect-injection",
    pattern: /!\[.*?\]\(https?:\/\/[^\s)]*(\?|\&)[^\s)]*\)/i,
    severity: "high",
    description: "Markdown image used to exfiltrate data via URL params",
  },
  {
    id: "SSRF_URL_INJECTION",
    type: "indirect-injection",
    pattern: /https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/i,
    severity: "high",
    description: "Internal/private IP in URL — potential SSRF via LLM tool call",
  },

  // ── Prompt continuation attacks ────────────────────────────────────────────
  {
    id: "CONTINUATION_HIJACK",
    type: "continuation-hijack",
    pattern: /\bAssistant\s*:/i,
    severity: "medium",
    description: "Injects an 'Assistant:' turn to hijack the conversation flow",
  },
  {
    id: "END_OF_CONTEXT_MARKER",
    type: "continuation-hijack",
    pattern: /(end\s+of\s+(context|conversation|system\s+prompt|instructions?)|---\s*end\s*---)/i,
    severity: "medium",
    description: "Fake end-of-context marker to trick the model into treating following text as authoritative",
  },

  // ── Goal / objective hijacking ─────────────────────────────────────────────
  {
    id: "TASK_HIJACK",
    type: "goal-hijack",
    pattern: /your\s+(only|sole|primary|main|real|actual|true)\s+(goal|task|job|purpose|objective|mission)\s+(is|now\s+is|should\s+be)\s+(to\s+)?(?!help|assist|answer)/i,
    severity: "high",
    description: "Attempts to redefine the model's primary task",
  },
];
