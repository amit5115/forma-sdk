# FORMA SDK

**Make non-compliance impossible — in one line of code.**

FORMA doesn't just record what your AI did; it **blocks non-compliant decisions before they execute**. Add `enforce=[...]` and PII leaks, prompt injections, and policy violations are stopped at runtime — then every decision is cryptographically signed and mapped to RBI, DPDP, EU AI Act, and ISO 42001.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## Install

```bash
pip install forma-sdk
```

Import name is `trustlayer` (the legacy alias `provn` also works):

```python
import trustlayer as tl
```

## Quickstart — runtime enforcement

```python
import trustlayer as tl

tl.init(api_key="tl_live_YOUR_KEY")   # from forma.2bd.net → Settings

@tl.agent(
    purpose="Loan application evaluation",
    risk_level="HIGH",
    enforce=["rbi_ml_risk", "dpdp"],   # ← blocks violations BEFORE they run
)
def approve_loan(application: dict) -> dict:
    return run_underwriting_model(application)
```

Now, before any LLM or tool call executes:

- An Aadhaar / PAN / card number in the prompt → **blocked** (DPDP)
- "Ignore previous instructions…" / jailbreaks → **blocked**
- "Auto-approve without review" → **blocked** (RBI human-review rule)

A blocked action raises `ComplianceViolation`, and every decision (allow / warn / block) lands in your signed audit trail. The gate runs **locally in ~1 ms** — no network hop in your request path.

```python
from trustlayer import ComplianceViolation

try:
    result = approve_loan(application)
except ComplianceViolation as e:
    print(e.reason)   # "PII detected in LLM prompt: Aadhaar number. ..."
```

## Zero-config tracking (no enforcement)

```python
import trustlayer as tl
tl.init(api_key="tl_live_YOUR_KEY")

# Every OpenAI / Anthropic / LangChain / LiteLLM call is now auto-captured —
# tokens, cost, latency, anomaly score — with no other code changes.
```

## Human approvals (EU AI Act Article 14 / RBI human review)

```python
@tl.track
@tl.require_approval(
    when=lambda result: result["amount"] > 1_000_000,   # only high-stakes
    message="Loan above ₹10L requires human review.",
)
def approve_loan(application: dict) -> dict:
    return run_underwriting_model(application)
```

The decision pauses in your FORMA Approvals inbox until a human approves or rejects. Fail-closed: a timeout or unreachable API is treated as a denial — a skipped review never silently passes.

---

## Policy packs

| Pack | Region | Enforces |
|------|--------|----------|
| `dpdp` | India | Aadhaar / PAN / card / phone blocked from prompts & tool args; consent-bypass blocked |
| `rbi_ml_risk` | India Banking | auto-approval-without-review blocked; fund-disbursal routed to approval |
| `eu_ai_act` | EU | human-oversight bypass (Art. 14) & logging suppression (Art. 12) blocked; PII protection |
| `iso42001` | Global | concealing AI involvement blocked |

---

## Manual step control

```python
import openai
import trustlayer as tl

tracker = tl.init(api_key="tl_live_YOUR_KEY", auto_capture=False)

@tracker.track(name="my-agent")
def my_agent(task: str) -> str:
    with tracker.llm_call(label="generate", model="gpt-4o", prompt=task) as step:
        resp = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": task}],
        )
        step.prompt_tokens     = resp.usage.prompt_tokens
        step.completion_tokens = resp.usage.completion_tokens
        return resp.choices[0].message.content

# For tools:  with tracker.tool_call("send_email", {"to": addr}): ...
```

## Kill switch

Pass `kill_switch=True` to `@tl.agent(...)` (or `tl.init(kill_switch=True)`). When you trigger a kill from the dashboard, the next LLM/tool call raises `KillSwitchTriggered` in under ~100 ms.

## CI/CD compliance gate

```bash
# Blocks the deploy (exit 1) if any agent is below the threshold
trustlayer gate --pre-deploy --fail-below 80
```

---

## `tl.init()` parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `api_key` | `str` | Your FORMA API key (`tl_live_…` / `tl_test_…`) |
| `enforce` | `list[str]` | Framework packs enforced on every call, e.g. `["dpdp"]` |
| `human_sponsor` | `str` | Accountable human (EU AI Act Art. 14 / RBI) |
| `auto_capture` | `bool` | Auto-patch OpenAI/Anthropic/LangChain/LiteLLM (default `True`) |
| `kill_switch` | `bool` | Start the process-level kill watcher (default `False`) |
| `compliance` | `list[str]` | Frameworks for scoring/reports |
| `agent_name` | `str` | Display name for ambient auto-captured runs |

---

## Node.js / TypeScript

```bash
npm install forma-sdk
```

```ts
import * as tl from "forma-sdk";

tl.init({ apiKey: "tl_live_YOUR_KEY" });

const myAgent = tl.track(
  async (task: string) => { /* your code */ return "done"; },
  { name: "my-agent" },
);
```

> **Note:** runtime enforcement (`enforce`), `agent`, and approvals are **Python-only** today. The Node SDK currently provides auto-tracking (`init` + `track`); enforcement parity is on the roadmap.

---

## Dashboard & docs

- Dashboard: **[forma.2bd.net](https://forma.2bd.net)**
- Developer guide: [forma.2bd.net/developer-guide](https://forma.2bd.net/developer-guide)
- Generate a tailored snippet: [forma.2bd.net/snippet-generator](https://forma.2bd.net/snippet-generator)

## License

MIT — see [LICENSE](LICENSE).
