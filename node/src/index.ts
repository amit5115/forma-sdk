/**
 * PROVN SDK — AI Agent Governance in 3 lines.
 *
 * @example
 * ```typescript
 * import * as provn from "provn-sdk";
 *
 * provn.init({
 *   apiKey: "tl_live_...",
 *   humanSponsor: "ops@company.com",
 * });
 *
 * const myAgent = provn.track(async (task: string) => {
 *   // your existing code — unchanged
 *   return "done";
 * }, { name: "my-agent" });
 *
 * await myAgent("Hello from PROVN!");
 * ```
 */

import * as crypto from "crypto";
import { ProvnClient, ProvnConfig, ProvnGateBlock, StepRecord } from "./client";

export { ProvnClient, ProvnAPIError, ProvnGateBlock } from "./client";
export type { ProvnConfig, StepRecord, GateResult } from "./client";

let _client: ProvnClient | null = null;

export function init(config: ProvnConfig): ProvnClient {
  _client = new ProvnClient(config);
  return _client;
}

export function getClient(): ProvnClient {
  if (!_client) throw new Error("Call provn.init() before using the SDK.");
  return _client;
}

// ── Step builder ──────────────────────────────────────────────────────────────

export class RunContext {
  readonly runId: string;
  readonly agentName: string;
  readonly steps: StepRecord[] = [];
  totalTokens = 0;
  totalCostUsd = 0;
  private stepCounter = 0;

  constructor(runId: string, agentName: string) {
    this.runId = runId;
    this.agentName = agentName;
  }

  addLlmStep(opts: {
    label: string;
    model: string;
    promptTokens?: number;
    completionTokens?: number;
    costUsd?: number;
    durationMs?: number;
  }): void {
    this.stepCounter++;
    const p = opts.promptTokens ?? 0;
    const c = opts.completionTokens ?? 0;
    this.totalTokens += p + c;
    this.totalCostUsd += opts.costUsd ?? 0;
    this.steps.push({
      step_number: this.stepCounter,
      step_type: "llm",
      label: opts.label,
      model: opts.model,
      prompt_tokens: p,
      completion_tokens: c,
      cost_usd: opts.costUsd,
      duration_ms: opts.durationMs,
      status: "success",
    });
  }

  addToolStep(opts: {
    toolName: string;
    toolArgs?: Record<string, unknown>;
    toolResult?: string;
    durationMs?: number;
    error?: string;
  }): void {
    this.stepCounter++;
    this.steps.push({
      step_number: this.stepCounter,
      step_type: "tool",
      label: `Tool: ${opts.toolName}`,
      tool_name: opts.toolName,
      tool_args: opts.toolArgs,
      tool_result: opts.toolResult,
      duration_ms: opts.durationMs,
      error: opts.error,
      status: opts.error ? "error" : "success",
    });
  }
}

// ── @provn.track ──────────────────────────────────────────────────────────────

export interface TrackOptions {
  name?: string;
  version?: string;
}

type AsyncFn<A extends unknown[], R> = (...args: A) => Promise<R>;

export function track<A extends unknown[], R>(
  fn: AsyncFn<A, R>,
  opts: TrackOptions = {}
): AsyncFn<A, R> {
  const agentName = opts.name ?? fn.name ?? "agent";
  const version = opts.version ?? "1.0.0";

  return async (...args: A): Promise<R> => {
    if (!_client) return fn(...args);

    const runId = `run_${crypto.randomBytes(6).toString("hex")}`;
    const ctx = new RunContext(runId, agentName);
    const startedAt = new Date().toISOString();
    const t0 = Date.now();
    let status = "success";
    let errorMsg: string | undefined;

    try {
      const result = await fn(...args);
      return result;
    } catch (err: unknown) {
      status = "failed";
      errorMsg = err instanceof Error ? err.message : String(err);
      throw err;
    } finally {
      const durationMs = Date.now() - t0;
      const endedAt = new Date().toISOString();
      const sig = `hmac-sha256:${crypto.createHmac("sha256", _client.apiKey).update(runId).digest("hex").slice(0, 32)}`;
      _client.submitRun({
        run_id: runId,
        agent_name: agentName,
        agent_version: version,
        human_sponsor: _client.humanSponsor,
        started_at: startedAt,
        ended_at: endedAt,
        duration_ms: durationMs,
        status,
        steps: ctx.steps,
        total_tokens: ctx.totalTokens,
        total_cost_usd: ctx.totalCostUsd,
        error: errorMsg,
        signature: sig,
      }).catch(() => {/* never fail the agent */});
    }
  };
}

// ── provn.gate() ──────────────────────────────────────────────────────────────

export async function gate(
  agentId: string,
  opts: { actionType?: string; prompt?: string; raiseOnBlock?: boolean } = {}
): Promise<{ decision: string; reason: string }> {
  if (!_client) return { decision: "allow", reason: "PROVN not initialised" };

  const result = await _client.checkGate(
    agentId,
    opts.actionType ?? "llm_call",
    opts.prompt
  );

  if ((opts.raiseOnBlock ?? true) && result.decision === "block") {
    throw new ProvnGateBlock(result.decision, result.reason, result.rule_triggered);
  }

  return result;
}
