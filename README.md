# FORMA SDK — v2.3.0

**Make non-compliance impossible — in one line of code.**

FORMA doesn't just record what your AI did; it **blocks non-compliant decisions before they execute**. Add `enforce=[...]` and PII leaks, prompt injections, and policy violations are stopped at runtime — then every decision is HMAC-signed and mapped to RBI, DPDP, EU AI Act, and ISO 42001.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## Install

```bash
pip install forma-sdk
```

Import name is `trustlayer`:

```python
import trustlayer as tl
```

## Quickstart — runtime enforcement (zero-touch)

```python
import trustlayer as tl

# One call. Enforcement is process-wide on every LLM/tool call — no decorators,
# no context managers, no edits inside your business logic.
tl.init(
    api_key="tl_live_YOUR_KEY",   # from formaai.in → Settings
    human_sponsor="ops@company.com",
    enforce=["rbi_ml_risk", "dpdp"],   # ← blocks violations BEFORE they run
)

# Prove enforcement is live — 4 adversarial probes, no network:
result = tl.verify()
assert result["verified"], f"Gate not working: {result['summary']}"

# Your existing code is unchanged.
result = run_underwriting_model(application)
```

Now, before any LLM or tool call executes:

- An Aadhaar / PAN / GSTIN / IFSC / Indian Passport / card number → **blocked** (DPDP)
- "Ignore previous instructions…" / jailbreaks → **blocked**
- "Auto-approve without review" → **blocked** (RBI human-review rule)

A blocked action raises `ComplianceViolation`. The gate runs **locally in < 1 ms** — no network hop. Tool calls get a **1.25× threat multiplier**; dangerous tool names (exec, shell, rm, delete, drop) add a further +0.35.

> **Init-time validation:** `enforce=["dpdpp"]` (typo) raises `ValueError` immediately with a link to the docs — misconfigurations are caught before any traffic flows.

## Multiple agents — `tl.register()` / `agents=` (still zero edits)

Map your **existing functions** to agents without touching their bodies:

```python
import trustlayer as tl
from my_app import approve_loan, validate_kyc, detect_fraud

tl.init(
    api_key="tl_live_YOUR_KEY",
    agents={
        "kyc-validator":  validate_kyc,                                        # bare callable
        "loan-approval":  {"fn": approve_loan, "enforce": ["rbi_ml_risk", "dpdp"],
                           "risk_level": "HIGH"},
        "fraud-detector": {"fn": detect_fraud, "enforce": ["dpdp"]},
    },
)

# Or register after init (decorator form also works):
tl.register("loan-approval", approve_loan, enforce=["rbi_ml_risk"], risk_level="HIGH")

# Call them exactly as before — each governed and attributed independently.
result = approve_loan(application)
```

```python
from trustlayer import ComplianceViolation

try:
    result = approve_loan(application)
except ComplianceViolation as e:
    print(e.reason)   # "PII detected in LLM prompt: Aadhaar number. ..."
```

## Observability API (v2.3.0)

Three functions let you inspect the in-process gate from health checks, startup scripts, or unit tests — no network calls needed.

### `tl.verify()` — Prove enforcement is active

Runs 4 adversarial self-test probes against the local gate. Use at startup to confirm the gate is wired before any real traffic flows.

```python
tl.init(api_key="tl_live_...", enforce=["dpdp"])
result = tl.verify()
# → {verified: True, probes_passed: 4, probes_total: 4, summary: "4/4 probes passed — gate is active"}

# Probes (all local — no network):
#   1. Aadhaar PII → must block
#   2. Indian PAN → must block
#   3. Canonical jailbreak → must block
#   4. Clean benign prompt → must allow
#   5. Unauthorized tool (if authorized_actions set) → must block
```

### `tl.status()` — Real-time enforcement state

Returns a live snapshot of the gate — decision counts, top blocked rules, circuit-breaker state:

```python
s = tl.status()
# → {
#     "version": "2.3.0",
#     "enforcement_active": True,
#     "decisions_total": 1847,
#     "decisions_blocked": 23,
#     "decisions_warned": 4,
#     "decisions_allowed": 1820,
#     "top_rule_hits": {"pii_in_prompt": 18, "threat_prompt_injection": 5},
#     "circuit_breaker_open": False,
#     "kill_switch_active": False,
#     "last_policy_sync": "2026-06-17T10:15:32Z",
#     ...
# }
```

### `tl.preview()` — Dry-run gate check

Simulate what the gate would decide for any prompt — no side effects, no `ComplianceViolation`, no audit log entry:

```python
r = tl.preview("My Aadhaar is 1234 5678 9012")
# → {"decision": "block", "rule_id": "pii_in_prompt", "reason": "PII detected: Aadhaar number..."}

r = tl.preview("What is the loan status?")
# → {"decision": "allow", "rule_id": None, "reason": None}

# Test a tool call (higher threat multiplier):
r = tl.preview("drop tables", action_type="tool_call", tool_name="exec_sql")
# → {"decision": "block", ...}
```

### `trustlayer verify-decisions` — Tamper-evident audit CLI

Every gate decision is HMAC-SHA256 signed before buffering. This CLI command fetches the log and verifies every signature:

```bash
trustlayer verify-decisions
# ✓ 47 decisions verified (0 tampered, 0 unsigned)
#   Blocked: 8 | Warned: 3 | Allowed: 36
#   Top rule: pii_aadhaar (5 hits)

trustlayer verify-decisions --agent loan-approval-agent --limit 500
# exits 1 if any decision fails verification — wire into CI
```

---

## Zero-config tracking (no enforcement)

```python
import trustlayer as tl
tl.init(api_key="tl_live_YOUR_KEY")

# Every OpenAI / Anthropic / LangChain / LiteLLM call is auto-captured —
# tokens, cost, latency, anomaly score — with no other code changes.
```

## Human approvals (EU AI Act Article 14 / RBI human review)

```python
tl.init(
    api_key="tl_live_YOUR_KEY",
    require_approval_when=lambda ctx: ctx.get("amount", 0) > 1_000_000,
    approval_message="Loan above ₹10L requires human review.",
)
result = approve_loan(application)   # pauses for sign-off on high-stakes calls
```

---

## Policy packs

| Pack | Region | Enforces |
|------|--------|----------|
| `dpdp` | India | Aadhaar / PAN / GSTIN / IFSC / Passport / card / phone / DoB blocked; consent-bypass blocked |
| `rbi_ml_risk` | India Banking | auto-approval-without-review blocked; fund-disbursal routed to approval |
| `eu_ai_act` | EU | human-oversight bypass (Art. 14) & logging suppression (Art. 12) blocked |
| `iso42001` | Global | concealing AI involvement blocked |

## PII patterns (17 — India + global)

Aadhaar · PAN · GSTIN (15-char) · IFSC code · Indian Passport · Driving License · Date of Birth (with context) · Visa card · Mastercard · Amex · CVV · phone · email · SSN · generic credit card · IBAN · passport (generic)

---

## Kill switch

Pass `kill_switch=True` to `tl.init()`. When you trigger a kill from the dashboard, the next LLM/tool call raises `KillSwitchTriggered` in < 100 ms.

## CI/CD compliance gate

```bash
trustlayer gate --pre-deploy --fail-below 80
trustlayer verify-decisions --limit 500   # tamper check in CI
```

---

## Production reliability (v2.3.0)

| Feature | Behaviour |
|---------|-----------|
| **Policy sync circuit breaker** | Stops retry storms after 5 consecutive server failures; auto-resets after 5 min. Gate stays up using the last known policy. |
| **Disk-backed decision buffer** | Unflushed decisions are persisted to `~/.forma/pending_decisions.jsonl` on flush failure and replayed on next startup — no audit data lost on transient outages. |
| **HMAC-signed entries** | Every buffered gate decision is signed with your API key before queuing — tamper-detectable by `verify-decisions` CLI or `cache.verify_log()`. |

---

## `tl.init()` parameters (all 25)

| Parameter | Description |
|-----------|-------------|
| `api_key` | FORMA API key (or `FORMA_API_KEY` env). |
| `api_url` | Backend URL override. |
| `agent_name` | Display name for ambient auto-captured runs. |
| `human_sponsor` | Accountable human on the audit record. |
| `auto_capture` (`True`) | Auto-patch OpenAI/Anthropic/LiteLLM/LangChain. |
| `kill_switch` (`False`) | Start global process-level kill-switch watcher. |
| `gate` (`True`) | Pre-check every auto-captured call through the compliance gate. |
| `compliance` | Frameworks for scoring/reports (`EU_AI_ACT`, `DPDP`, `RBI_MRM`, `ISO_42001`). |
| `ambient_runs` (`True`) | Create signed runs for auto-captured calls. |
| `enforce` | Policy packs blocked locally (`dpdp`, `rbi_ml_risk`, `eu_ai_act`, `iso42001`). Typos raise `ValueError` at init time. |
| `agents` | Zero-edit multi-agent map. `{"name": fn}` or `{"name": {"fn": fn, "enforce": [...], ...}}`. |
| `purpose` | Plain-English purpose stored in the identity passport. |
| `risk_level` (`"MEDIUM"`) | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL`. |
| `authorized_actions` | Allow-list of tool names; gate blocks others. |
| `drift_threshold` (`0.15`) | Behavioural drift threshold. |
| `max_cost_usd` | Hard per-run cost cap. |
| `require_approval_when` | Predicate `ctx→bool`; `True` pauses for human approval. |
| `approval_message` / `approval_title` | Text in the Approvals inbox. |
| `approval_timeout` (`3600`) | Seconds to wait for a decision. |
| `approval_poll_interval` (`5`) | Seconds between inbox polls. |
| `approval_via` (`"forma"`) | Approval channel. |
| `timeout` (`10`) | HTTP timeout seconds. |
| `max_retries` (`2`) | Transport retry attempts. |
| `fail_closed` (`False`) | Block when the gate is unreachable (default: fail open). |

## `tl.register(name, fn, **cfg)` — the second entry point

Binds one existing function to a governed agent. Works as a decorator too. Accepts the same full governance argument set as `init(agents={...})` per-agent config (unknown keyword → `TypeError`).

### When to use which

| Use… | When |
|------|------|
| `tl.init(agents={...})` | All agent functions importable at init() call. Simplest. |
| `tl.register(name, fn, ...)` | Function defined/imported after init(), decorator form, or dynamic registration. |

---

## Node.js / TypeScript

> **Coming soon.** Runtime enforcement (`enforce`) and approvals are **Python-only** today.

---

## Dashboard & docs

- Dashboard: **[formaai.in](https://formaai.in)**
- Developer guide: [formaai.in/developer-guide](https://formaai.in/developer-guide)
- Snippet generator: [formaai.in/snippet-generator](https://formaai.in/snippet-generator)

## License

MIT — see [LICENSE](LICENSE).
