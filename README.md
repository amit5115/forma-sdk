# forma-sdk — The AI Agent Firewall

**Block unauthorized actions, PII leaks, and jailbreaks — before they execute.**

FORMAAI sits between your AI agents and your business. Every LLM call is gated locally in under 1ms — Aadhaar, PAN, GSTIN, UPI and 14 more India PII patterns blocked before the model sees them. One line of code.

[![PyPI](https://img.shields.io/pypi/v/forma-sdk?label=pip%20install%20forma-sdk)](https://pypi.org/project/forma-sdk/)
[![npm](https://img.shields.io/npm/v/forma-sdk?label=npm%20install%20forma-sdk)](https://www.npmjs.com/package/forma-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Install

**Python**
```bash
pip install forma-sdk
```

**Node.js**
```bash
npm install forma-sdk
```

---

## Python SDK — Quickstart

Import as `tl` (package installs as `forma-sdk`, import name is `trustlayer`):

```python
import trustlayer as tl
```

### Zero-config with preset

```python
import trustlayer as tl

tl.init(api_key="tl_live_...", preset="india_fintech")

# Verify gate is live — runs 4 adversarial probes locally, no network:
v = tl.verify()
assert v["verified"], f"Gate not working: {v['summary']}"
```

Available presets: `india_fintech` · `india_health` · `india` · `global`

### Add to existing code — zero edits inside your functions

```python
# Your existing code — bodies untouched:
import openai
client = openai.OpenAI(api_key="sk-...")

def approve_loan(context):
    return client.chat.completions.create(model="gpt-4o-mini",
        messages=[{"role": "user", "content": context}])

def validate_kyc(doc):
    return client.chat.completions.create(model="gpt-4o-mini",
        messages=[{"role": "user", "content": doc}])

# Add these 2 lines BEFORE your first LLM call:
import trustlayer as tl
tl.init(api_key="tl_live_...", enforce=["dpdp", "rbi_ml_risk"])

# That's it. Now every call is gated:
approve_loan("Customer Aadhaar 2341 1234 1236")  # → ComplianceViolation (blocked)
approve_loan("Standard 5-year home loan")         # → runs normally
```

### Named agents — per-function policies

```python
from my_app import approve_loan, validate_kyc, detect_fraud

tl.init(
    api_key="tl_live_...",
    agents={
        "loan-approval": {"fn": approve_loan, "enforce": ["rbi_ml_risk", "dpdp"], "risk_level": "HIGH"},
        "kyc-validator":  {"fn": validate_kyc,  "enforce": ["dpdp"]},
        "fraud-detector": detect_fraud,   # bare callable — uses process-wide enforce
    },
)
```

### Register after init

```python
tl.init(api_key="tl_live_...")

# Later — e.g. inside a FastAPI startup hook:
tl.register("payment-agent", process_payment, enforce=["dpdp"], risk_level="HIGH")

# Or as a decorator:
@tl.register("summarizer", enforce=["eu_ai_act"])
def summarize(text: str) -> str:
    return client.chat.completions.create(...)
```

### Handle violations

```python
from trustlayer import ComplianceViolation

try:
    approve_loan("Aadhaar 2341 1234 1236")
except ComplianceViolation as e:
    print(e.reason)   # "PII detected: Aadhaar number — Remove and use customer_id"
    # Block is already in your audit trail at formaai.in/dashboard
```

### All tl.init() parameters

| Parameter | Type | Description |
|---|---|---|
| `api_key` | `str` | Your API key (`tl_live_...` or `tl_test_...`) |
| `preset` | `str` | `"india_fintech"` / `"india_health"` / `"india"` / `"global"` |
| `enforce` | `list[str]` | Packs: `dpdp` `rbi_ml_risk` `eu_ai_act` `hipaa` `pci_dss` `gdpr` `iso42001` `soc2` `nist` `ai_safety` |
| `compliance` | `list[str]` | Frameworks: `DPDP` `RBI_MRM` `EU_AI_ACT` `HIPAA` `PCI_DSS` `GDPR` `ISO_42001` `SOC2` `NIST` |
| `risk_level` | `str` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `agents` | `dict` | Bulk-register functions: `{"name": fn}` or `{"name": {"fn": fn, "enforce": [...]}}` |
| `kill_switch` | `bool` | Enable kill switch — freeze agent instantly from dashboard |
| `require_approval_when` | `callable` | `lambda ctx: ctx["amount"] > 1_000_000` — human-in-the-loop |
| `authorized_actions` | `list[str]` | Tool allow-list — blocks anything not in this list |
| `drift_threshold` | `float` | `0.15` — alert when behaviour drifts >15% from baseline |
| `max_cost_usd` | `float` | Hard cap on LLM spend per run |
| `human_sponsor` | `str` | Accountable person email (for audit trail) |

### Observability

```python
# Dry-run — never blocks, returns the gate decision:
r = tl.preview("Aadhaar 2341 1234 1236")
print(r["decision"])   # "block"
print(r["reason"])     # "PII detected: Aadhaar number"

# Real-time enforcement status:
s = tl.status()
print(s["enforcement_active"])   # True
print(s["pii_check"])            # True

# Adversarial probes — confirm gate is working:
v = tl.verify()
print(v["verified"])             # True
print(v["probes_passed"])        # 4
```

---

## Node.js SDK — Quickstart

```typescript
import * as forma from "forma-sdk";
import { FormaGateBlock } from "forma-sdk";
```

### Zero-config with preset

```typescript
import * as forma from "forma-sdk";
forma.init({ apiKey: "tl_live_...", preset: "india_fintech" });

const v = forma.verify();
console.log(v.verified);        // true
console.log(v.probes_passed);   // >= 2
```

### Wrap OpenAI — every call auto-gated

```typescript
import OpenAI from "openai";
import * as forma from "forma-sdk";
import { FormaGateBlock } from "forma-sdk";

forma.init({ apiKey: "tl_live_...", preset: "india_fintech" });
const openai = forma.wrapOpenAI(new OpenAI({ apiKey: "sk-..." }), "loan-agent");

try {
  const res = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: userInput }],
  });
  return res.choices[0].message.content;
} catch (e) {
  if (e instanceof FormaGateBlock) {
    console.log(e.reason);  // "PII detected: Aadhaar number — use customer_id instead"
    // Block is in your audit trail at formaai.in/dashboard
  }
}
```

### Wrap Anthropic

```typescript
import Anthropic from "@anthropic-ai/sdk";
import * as forma from "forma-sdk";
import { FormaGateBlock } from "forma-sdk";

forma.init({ apiKey: "tl_live_...", preset: "india_fintech" });
const anthropic = forma.wrapAnthropic(new Anthropic({ apiKey: "sk-ant-..." }), "kyc-agent");

try {
  const msg = await anthropic.messages.create({
    model: "claude-sonnet-4-6", max_tokens: 1024,
    messages: [{ role: "user", content: userInput }],
  });
} catch (e) {
  if (e instanceof FormaGateBlock) {
    console.log(e.reason);
  }
}
```

### Manual gate check

```typescript
import * as forma from "forma-sdk";
import { FormaGateBlock } from "forma-sdk";

forma.init({ apiKey: "tl_live_...", preset: "india_fintech" });

// Gate any action before it executes:
try {
  await forma.gate("my-agent", { prompt: userInput, actionType: "llm_call" });
  // ... your LLM call here
} catch (e) {
  if (e instanceof FormaGateBlock) {
    console.log(e.reason);
  }
}
```

### forma.init() parameters (Node.js)

| Parameter | Type | Description |
|---|---|---|
| `apiKey` | `string` | Your API key (`tl_live_...` or `tl_test_...`) |
| `preset` | `string` | `"india_fintech"` / `"india_health"` / `"india"` / `"global"` |
| `enforce` | `string[]` | Same packs as Python SDK |
| `agentName` | `string` | Default agent name for gate calls |
| `killSwitch` | `boolean` | Enable kill switch |
| `authorizedActions` | `string[]` | Tool allow-list |
| `failClosed` | `boolean` | Block when API unreachable (default: false = fail-open) |

---

## What gets blocked

**India PII (17 patterns, all checksum-validated):**

| Pattern | Example | Validation |
|---|---|---|
| Aadhaar | `2341 1234 1236` · `2341-1234-1236` | Verhoeff check digit |
| PAN | `ABCDE1234F` | Structural |
| GSTIN | `29ABCDE1234F1Z5` | Base-36 checksum |
| UPI VPA | `ramesh@okhdfcbank` · `9876543210@paytm` | 30+ PSPs |
| Indian phone | `+91 98765 43210` | |
| IFSC | `HDFC0001234` | |
| Indian Passport | `A1234567` | |
| Visa/MC/Amex/CVV | `4111 1111 1111 1111` | |
| IBAN | `GB29NWBK60161331926819` | |

**Jailbreaks & injection attacks** — 99.7% corpus recall, <1ms, no ML model required.

---

## Enforcement packs

| Pack | Region | Blocks |
|---|---|---|
| `dpdp` | India | Aadhaar · PAN · GSTIN · UPI · all 17 PII patterns · consent bypass |
| `rbi_ml_risk` | India Banking | Auto-approve bypass · unreviewed credit decisions |
| `eu_ai_act` | EU | High-risk AI system misuse · transparency bypass |
| `hipaa` | US Healthcare | PHI in prompts · medical record PII |
| `pci_dss` | Global | Card numbers · CVV · IBAN |
| `gdpr` | EU | Personal data minimisation · consent bypass |
| `ai_safety` | Global | Injection · jailbreak · always-on baseline |
| `iso42001` | Global | AI management system policy |
| `soc2` | Global | Security policy violations |
| `nist` | Global | NIST AI RMF |

---

## Test mode

Use `tl_test_` keys for development — data is fully isolated from live:

```python
tl.init(api_key="tl_test_YOUR_KEY", enforce=["dpdp"])
```

---

## Requirements

**Python:** 3.8+ · No required dependencies (openai/anthropic/litellm/langchain auto-detected)

**Node.js:** 18+ · `openai ≥4.0` · `@anthropic-ai/sdk ≥0.20` · TypeScript 5+ recommended

---

## Links

- Dashboard: [formaai.in](https://formaai.in)
- Developer docs: [formaai.in/developer-guide](https://formaai.in/developer-guide)
- API reference: [api.formaai.in/docs](https://api.formaai.in/docs)
- Issues: [github.com/amit5115/forma-sdk](https://github.com/amit5115/forma-sdk)
