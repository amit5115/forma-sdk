/**
 * FORMA SDK for Node.js — The AI Agent Firewall
 *
 * Blocks unauthorized actions, PII leaks, and risky decisions before
 * they execute. One line of code. Works with OpenAI, Anthropic and any
 * Node.js application.
 *
 * @example
 * ```typescript
 * import * as forma from "forma-sdk";
 *
 * // Zero-config (after `forma setup`):
 * forma.init();
 *
 * // Or explicit:
 * forma.init({ apiKey: "tl_live_...", preset: "india_fintech" });
 *
 * // Gate any action:
 * await forma.gate("loan-agent", { prompt: userInput });
 *
 * // Wrap OpenAI — every call auto-gated:
 * const openai = forma.wrapOpenAI(new OpenAI({ apiKey: "..." }));
 *
 * // Preview (dry-run, never throws):
 * const r = forma.preview("Aadhaar 2341 1234 1236");
 * // r.decision === "block"
 *
 * // Verify enforcement is live:
 * const v = forma.verify();
 * // v.verified === true, v.probes_passed === 4
 * ```
 *
 * @module forma-sdk
 */

export {
  FormaClient,
  FormaGateBlock,
  FormaAPIError,
} from "./client";

export type {
  FormaConfig,
  GateOpts,
  GateResult,
  PreviewResult,
  VerifyResult,
  StatusResult,
  StepRecord,
} from "./client";

import { FormaClient, FormaConfig, GateOpts, GateResult, PreviewResult, VerifyResult, StatusResult } from "./client";

// ── Module-level client (tl.init() / tl.preview() style) ─────────────────────

let _client: FormaClient | null = null;

/** Initialize FORMA — call once at the top of your app. */
export function init(config: FormaConfig = {}): FormaClient {
  _client = new FormaClient(config);
  return _client;
}

/** Returns the active client (throws if init() not called). */
export function getClient(): FormaClient {
  if (!_client) {
    // Auto-init from env/config file with no enforce — still useful for API calls
    _client = new FormaClient({});
  }
  return _client;
}

/**
 * Gate an action — checks locally (instant) then server.
 * Throws FormaGateBlock if blocked (raiseOnBlock=true by default).
 */
export async function gate(agentId: string, opts: GateOpts = {}): Promise<GateResult> {
  return getClient().gate(agentId, opts);
}

/**
 * Dry-run gate check — never throws, never blocks, returns the decision.
 * Use this to test FORMA without affecting your application flow.
 */
export function preview(prompt: string, actionType: "llm_call" | "tool_call" = "llm_call"): PreviewResult {
  return getClient().preview(prompt, actionType);
}

/**
 * Run adversarial probes against the local gate.
 * Returns { verified: true } when all probes pass — Aadhaar/PAN block + clean allow.
 */
export function verify(): VerifyResult {
  return getClient().verify();
}

/** Real-time enforcement status — active packs, pii_check, frameworks etc. */
export function status(): StatusResult {
  return getClient().status();
}

/**
 * Wrap an OpenAI client so every chat.completions.create() is auto-gated.
 * @example
 * const openai = forma.wrapOpenAI(new OpenAI({ apiKey: "sk-..." }), "loan-agent");
 */
export function wrapOpenAI<T extends { chat: { completions: { create: (...args: unknown[]) => unknown } } }>(
  client: T, agentId = "openai-agent"
): T {
  return getClient().wrapOpenAI(client, agentId);
}

/**
 * Wrap an Anthropic client so every messages.create() is auto-gated.
 * @example
 * const anthropic = forma.wrapAnthropic(new Anthropic({ apiKey: "sk-ant-..." }), "kyc-agent");
 */
export function wrapAnthropic<T extends { messages: { create: (...args: unknown[]) => unknown } }>(
  client: T, agentId = "anthropic-agent"
): T {
  return getClient().wrapAnthropic(client, agentId);
}
