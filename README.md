# FORMA SDK

**AI agent compliance, in 2 lines of code.**

FORMA automatically generates signed compliance certificates and cryptographic audit trails for every AI agent run — covering RBI, DPDP, EU AI Act, and ISO 42001. No consultants. No manual reporting.

[![PyPI version](https://badge.fury.io/py/forma-sdk.svg)](https://pypi.org/project/forma-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## Install

```bash
pip install forma-sdk
```

## Quickstart

```python
import trustlayer as tl

# Initialize once at app startup
tl.init(
    api_key="tl_live_YOUR_KEY_HERE",   # from forma.2bd.net → Settings
    human_sponsor="your@email.com",
)

# Decorate any agent function — zero other changes needed
@tl.track
def my_agent(query: str) -> str:
    # Your LLM calls here — auto-captured
    return "response"

# Every call now generates a signed audit trail
result = my_agent("Approve this loan application")
```

That's it. FORMA captures input, output, decision, confidence, tokens, latency, and anomaly score for every run — and generates a compliance certificate you can show regulators.

---

## Features

| Feature | What it does |
|---------|-------------|
| **Auto-tracking** | `@tl.track` captures every run with zero code changes |
| **Compliance certificates** | Signed PDF/JSON certs for RBI, DPDP, EU AI Act, ISO 42001 |
| **Kill switch** | Instantly halt any agent across all instances |
| **Anomaly detection** | Real-time drift and outlier detection on every run |
| **Transparency chain** | Cryptographic Merkle tree audit log |
| **Evidence bundles** | One-click export for auditors |
| **Gate checks** | Block actions before they execute |

---

## Dashboard

Sign up at **[forma.2bd.net](http://forma.2bd.net)** to get your API key and access the full compliance dashboard.

---

## Advanced Usage

### Manual run tracking

```python
from trustlayer import PROVNClient, AgentRun
import uuid

client = PROVNClient(api_key="tl_live_YOUR_KEY")

run = AgentRun(
    run_id=str(uuid.uuid4()),
    agent_id="agt_YOUR_AGENT_ID",
    agent_name="LoanApprovalAgent",
    agent_version="2.1",
    input_summary="Loan application for ₹5L",
    output_summary="Approved with 94% confidence",
    decision="approve",
    confidence_score=0.94,
)
client.send_run(run)
```

### Gate checks (block before execute)

```python
import trustlayer as tl

allowed = tl.gate.check(
    agent_id="agt_YOUR_AGENT_ID",
    action_type="financial_decision",
    payload={"amount": 500000, "customer_id": "C123"}
)

if not allowed:
    raise ValueError("Action blocked by compliance gate")
```

### Kill switch

```python
import trustlayer as tl

# Check if agent is killed before running
tl.gate.assert_alive(agent_id="agt_YOUR_AGENT_ID")
```

### OpenAI / LLM auto-capture

```python
import trustlayer as tl
import openai

tl.init(api_key="tl_live_YOUR_KEY", human_sponsor="you@company.com")

# Patch OpenAI — all calls auto-tracked
tl.auto.patch_openai(openai)

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Should I approve this loan?"}]
)
# ↑ This run is automatically logged to FORMA
```

---

## Compliance Coverage

| Framework | Coverage |
|-----------|---------|
| **RBI MRM Guidelines** | Model risk, audit trails, human oversight |
| **DPDP Act (India)** | Data processing records, consent logging |
| **EU AI Act** | High-risk AI documentation, conformity |
| **ISO 42001** | AI management system evidence |

---

## API Reference

Full API docs: [forma.2bd.net/docs](http://forma.2bd.net/docs)

### `tl.init()`

| Parameter | Type | Description |
|-----------|------|-------------|
| `api_key` | `str` | Your FORMA API key |
| `human_sponsor` | `str` | Email of accountable human |
| `agent_name` | `str` | Default agent name |
| `kill_switch` | `bool` | Enable kill switch checks (default: False) |
| `gate` | `bool` | Enable gate checks (default: True) |
| `compliance` | `list[str]` | Frameworks: `["rbi", "dpdp", "eu_ai_act"]` |

---

## Examples

See the [`examples/`](examples/) folder for:
- `basic_agent.py` — minimal integration
- `real_customer_walkthrough.py` — full compliance flow
- `my_existing_app.py` — adding FORMA to an existing app

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).

---

## Support

- Docs: [forma.2bd.net/developer-guide](http://forma.2bd.net/developer-guide)
- Issues: [github.com/amit5115/forma-sdk/issues](https://github.com/amit5115/forma-sdk/issues)
