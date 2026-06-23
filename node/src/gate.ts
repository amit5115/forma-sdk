/**
 * FORMA Local Gate — TypeScript port of Python gate_local.py
 * Evaluates prompts locally in <1ms — no network hop on the critical path.
 * PII patterns + threat detection keep sensitive data from leaving the process.
 */

// ── Unicode normalization + homoglyph defence ─────────────────────────────────
const HOMOGLYPHS: Record<string, string> = {
  "І": "I", "і": "i", "р": "p", "Р": "P", "а": "a", "А": "A",
  "е": "e", "Е": "E", "о": "o", "О": "O", "с": "c", "С": "C",
  "х": "x", "Х": "X", "ѕ": "s", "ν": "v", "ɑ": "a", "ɡ": "g",
};

export function normalize(text: string): string {
  // Replace Cyrillic/Greek homoglyphs with ASCII equivalents before scanning
  return Array.from(text).map(ch => HOMOGLYPHS[ch] ?? ch).join("");
}

// ── India PII patterns ────────────────────────────────────────────────────────
interface PiiPattern { label: string; pattern: RegExp; }

const PII_PATTERNS: PiiPattern[] = [
  // Core India PII
  { label: "Aadhaar number",  pattern: /\b(?:\d{4}[\s,./\-]?\d{4}[\s,./\-]?\d{4}|\d(?:[\s,.]\d){11})\b/g },
  { label: "Indian PAN",      pattern: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { label: "SSN",             pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { label: "Email address",   pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g },
  { label: "Phone number",    pattern: /\b(?:\+?91[\-\s]?)?[6-9]\d{4}[\s\-]?\d{5}\b/g },

  // India additions (DPDP moat)
  { label: "GSTIN",           pattern: /\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b/g },
  { label: "UPI ID",          pattern: /\b[a-zA-Z0-9][a-zA-Z0-9.\-_]{1,98}@(?:ok[a-z]+|paytm|ybl|apl|upi|ibl|axl|sbi|hdfcbank|hdfc|icici|axisbank|axis|kotak|fbl|yapl|jupiteraxis|barodampay|airtel|jio|freecharge|cnrb|idfcfirst|dbs|indus|abfspay|kbl|federal|pingpay|naviaxis|rmhdfc|waaxis|yesg|timecosmos)\b/gi },
  { label: "Indian Passport", pattern: /\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b/g },
  { label: "IFSC code",       pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g },
  { label: "Driving License", pattern: /\bDL[-\s]?\d{13}\b/gi },
  { label: "Date of birth",   pattern: /(?:dob|date[\s._-]?of[\s._-]?birth)[:\s]*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}/gi },

  // Cards (space-separated only — dashes = ref numbers)
  { label: "Visa card",       pattern: /(?<![0-9\-])4\d{3}\s?\d{4}\s?\d{4}\s?\d{1,4}(?![0-9\-])/g },
  { label: "Mastercard",      pattern: /(?<![0-9\-])5[1-5]\d{2}\s?\d{4}\s?\d{4}\s?\d{4}(?![0-9\-])/g },
  { label: "Amex",            pattern: /(?<![0-9\-])3[47]\d{2}\s?\d{6}\s?\d{5}(?![0-9\-])/g },
  { label: "CVV",             pattern: /(?:cvv|cvc|security[\s._-]?code)\D{0,15}\d{3,4}/gi },
  { label: "Credit/Debit card", pattern: /\b(?:\d\s?){13,16}\b/g },

  // International
  { label: "IBAN",            pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g },
  { label: "Passport number", pattern: /\b[A-Z]\d{7}\b/g },
];

export function detectPii(text: string): string | null {
  const normalized = normalize(text);
  for (const { label, pattern } of PII_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(normalized)) return label;
  }
  return null;
}

// ── Threat detection ─────────────────────────────────────────────────────────
const FLAGS = "i";

const INJECTION_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  { label: "prompt_injection",    pattern: new RegExp(String.raw`ignore\s.{0,40}(safety|constraint|guard|rule|policy|previous|instruction|system)`, FLAGS) },
  { label: "jailbreak",          pattern: new RegExp(String.raw`(jailbreak|bypass|disable|override|circumvent)\s.{0,40}(safety|constraint|filter|guard|policy|system|rule)`, FLAGS) },
  { label: "credential_extract", pattern: new RegExp(String.raw`(reveal|expose|dump|show|leak|exfiltrate)\s.{0,40}(password|secret|api.?key|credential|token|key)`, FLAGS) },
  { label: "role_switch",        pattern: new RegExp(String.raw`(you are now|act as|pretend to be|roleplay as|switch to)\s.{0,40}(admin|root|unrestricted|jailbreak|DAN|god mode)`, FLAGS) },
  { label: "system_prompt_leak", pattern: new RegExp(String.raw`(print|output|repeat|show|tell me)\s.{0,30}(your\s)?(system\s)?prompt|instruction`, FLAGS) },
  { label: "approval_bypass",    pattern: new RegExp(String.raw`(skip|bypass|without|no need for)\s.{0,20}(human\s)?(approval|review|sign.off|authorization)|auto[\s-]?(approve|authorize)`, FLAGS) },
  { label: "compliance_bypass",  pattern: new RegExp(String.raw`(disable|bypass|skip|ignore)\s.{0,20}(compliance|regulatory|gdpr|dpdp|rbi|pci|hipaa|policy|guardrail)`, FLAGS) },
  { label: "tool_abuse",         pattern: new RegExp(String.raw`(exec|execute|run|shell|bash|rm|delete|drop|truncate|disable)\s.{0,20}(command|script|database|table|server|system|production)`, FLAGS) },
];

export interface ThreatResult {
  decision: "block" | "warn" | "allow";
  rule_id: string | null;
  reason: string;
}

export function detectThreat(text: string): ThreatResult {
  const normalized = normalize(text);
  for (const { label, pattern } of INJECTION_PATTERNS) {
    if (pattern.test(normalized)) {
      return {
        decision: "block",
        rule_id: `threat_${label}`,
        reason: `Blocked by FORMA Gate — ${label.replace(/_/g, " ")} detected.`,
      };
    }
  }
  return { decision: "allow", rule_id: null, reason: "No threat detected." };
}

// ── Pack → framework flags ────────────────────────────────────────────────────
export const PACK_FLAGS: Record<string, string> = {
  ai_safety: "ai_safety", dpdp: "dpdp", dpdp_act: "dpdp", dpdp_act_2023: "dpdp",
  rbi: "rbi", rbi_ml_risk: "rbi", rbi_mrm: "rbi",
  eu_ai_act: "eu_ai_act", euaiact: "eu_ai_act",
  gdpr: "gdpr", hipaa: "hipaa", pci_dss: "pci_dss",
  iso42001: "iso42001", soc2: "soc2", nist: "nist",
};

export const PII_PACKS = new Set(["ai_safety", "dpdp", "eu_ai_act", "gdpr", "hipaa", "pci_dss"]);

// ── Local policy evaluation ───────────────────────────────────────────────────
export interface Policy {
  agentName: string;
  piiCheck: boolean;
  injectionCheck: boolean;
  killActive: boolean;
  authorizedActions: string[] | null;
  frameworks: string[];
  enforce_packs: string[];
}

export function buildBootstrapPolicy(agentName: string, packs: string[], authorizedActions?: string[]): Policy {
  const flags = packs.map(p => PACK_FLAGS[p.toLowerCase()] ?? p.toLowerCase());
  return {
    agentName,
    piiCheck: flags.some(f => PII_PACKS.has(f)),
    injectionCheck: true,
    killActive: false,
    authorizedActions: authorizedActions ?? null,
    frameworks: [...new Set(flags)],
    enforce_packs: packs,
  };
}

export interface GateDecision {
  decision: "allow" | "warn" | "block";
  rule_id: string | null;
  reason: string;
}

export function evaluateLocal(
  policy: Policy,
  opts: { actionType: string; prompt?: string; toolName?: string; toolArgs?: unknown }
): GateDecision {
  if (policy.killActive) {
    return { decision: "block", rule_id: "kill_switch", reason: "Kill switch active — all actions blocked." };
  }

  if (opts.actionType === "tool_call" && opts.toolName && policy.authorizedActions) {
    if (!policy.authorizedActions.includes(opts.toolName)) {
      return { decision: "block", rule_id: "unauthorized_tool",
        reason: `Tool '${opts.toolName}' is not in the authorized actions list.` };
    }
  }

  // Injection check
  if (policy.injectionCheck) {
    const scanText = opts.prompt ?? (opts.toolArgs ? JSON.stringify(opts.toolArgs) : "");
    if (scanText) {
      const threat = detectThreat(scanText);
      if (threat.decision === "block") return threat;
    }
  }

  // PII check
  if (policy.piiCheck) {
    const scanText = [opts.prompt, opts.toolArgs ? JSON.stringify(opts.toolArgs) : ""].filter(Boolean).join(" ");
    const pii = detectPii(scanText);
    if (pii) {
      return {
        decision: "block",
        rule_id: "pii_in_prompt",
        reason: `PII detected: ${pii}. Blocked by FORMA Gate (${[...policy.frameworks].join(", ") || "PII protection"}).`,
      };
    }
  }

  return { decision: "allow", rule_id: null, reason: "Action permitted — all compliance checks passed." };
}
