import * as https from "https";
import * as http from "http";
import { URL } from "url";

export interface ProvnConfig {
  apiKey: string;
  humanSponsor?: string;
  baseUrl?: string;
  timeout?: number;
}

export interface RunPayload {
  run_id: string;
  agent_name: string;
  agent_version: string;
  human_sponsor: string;
  started_at: string;
  ended_at?: string;
  duration_ms?: number;
  status: string;
  steps?: StepRecord[];
  total_tokens?: number;
  total_cost_usd?: number;
  error?: string;
  signature?: string;
  metadata?: Record<string, unknown>;
}

export interface StepRecord {
  step_number: number;
  step_type: "llm" | "tool" | "retrieval" | "code";
  label: string;
  model?: string;
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  tool_result?: string;
  prompt_tokens?: number;
  completion_tokens?: number;
  cost_usd?: number;
  duration_ms?: number;
  error?: string;
  status?: string;
}

export interface GateResult {
  decision: "allow" | "block" | "warn";
  reason: string;
  rule_triggered?: string;
  checks?: unknown[];
}

export class ProvnAPIError extends Error {
  constructor(public statusCode: number, public detail: unknown) {
    super(`PROVN API ${statusCode}: ${JSON.stringify(detail)}`);
    this.name = "ProvnAPIError";
  }
}

export class ProvnGateBlock extends Error {
  constructor(public decision: string, public reason: string, public rule: string = "") {
    super(`Gate blocked [${rule}]: ${reason}`);
    this.name = "ProvnGateBlock";
  }
}

function request<T>(
  baseUrl: string,
  method: string,
  path: string,
  apiKey: string,
  body?: unknown,
  timeoutMs = 10_000
): Promise<T> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const data = body ? JSON.stringify(body) : undefined;
    const mod = url.protocol === "https:" ? https : http;

    const req = mod.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method,
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
          "User-Agent": "provn-node-sdk/0.6.0",
          ...(data ? { "Content-Length": Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString();
          try {
            const json = JSON.parse(raw);
            if (res.statusCode && res.statusCode >= 400) {
              reject(new ProvnAPIError(res.statusCode, json));
            } else {
              resolve(json as T);
            }
          } catch {
            reject(new Error(`Invalid JSON response: ${raw}`));
          }
        });
      }
    );

    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error("Request timeout")); });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

export class ProvnClient {
  private baseUrl: string;
  private timeout: number;
  readonly apiKey: string;
  readonly humanSponsor: string;

  constructor(config: ProvnConfig) {
    this.apiKey = config.apiKey;
    this.humanSponsor = config.humanSponsor ?? "";
    this.baseUrl = (config.baseUrl ?? process.env.FORMA_API_URL ?? "https://forma.2bd.net").replace(/\/$/, "");
    this.timeout = config.timeout ?? 10_000;
  }

  submitRun(payload: RunPayload): Promise<unknown> {
    return request(this.baseUrl, "POST", "/api/runs", this.apiKey, payload, this.timeout);
  }

  checkGate(agentId: string, actionType: string, prompt?: string, metadata?: Record<string, unknown>): Promise<GateResult> {
    return request(this.baseUrl, "POST", "/api/gate/check", this.apiKey, {
      agent_id: agentId,
      action_type: actionType,
      prompt,
      metadata: metadata ?? {},
    }, this.timeout);
  }

  getKillStatus(agentId: string): Promise<unknown> {
    return request(this.baseUrl, "GET", `/api/agents/${agentId}/kill-status`, this.apiKey, undefined, this.timeout);
  }

  createAgent(name: string, version = "1.0.0", riskClass = "medium", description = ""): Promise<unknown> {
    return request(this.baseUrl, "POST", "/api/agents", this.apiKey, {
      name, version, human_sponsor: this.humanSponsor, risk_class: riskClass, description,
    }, this.timeout);
  }
}
