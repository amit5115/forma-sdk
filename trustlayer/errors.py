"""
Typed error hierarchy for the FORMAAI SDK.

The HTTP transport (client.py) parses the API's standardized error body
(`{"error": {"code", "message", ...}}`) and raises the matching subclass, so
callers can catch a specific failure mode:

    from trustlayer import FormaAuthError, FormaRateLimitError, FormaError
    try:
        ...
    except FormaAuthError:
        ...        # bad/revoked key
    except FormaRateLimitError as e:
        time.sleep(e.retry_after)
    except FormaError:
        ...        # any other API/connection failure

Note: the decorator/enforcement flows still degrade gracefully (best-effort
reporting, configurable fail-open gate) — these types surface only when you opt
into raising, or on the few synchronous paths that re-raise.
"""
from __future__ import annotations

from typing import Optional


class FormaError(Exception):
    """Base class for all FORMAAI SDK errors."""

    def __init__(self, message: str, *, code: Optional[str] = None, status: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


class FormaConnectionError(FormaError):
    """Network failure: timeout, DNS, refused connection (after retries)."""


class FormaAuthError(FormaError):
    """401/403 — the API key is missing, invalid, revoked, or lacks permission."""


class FormaRateLimitError(FormaError):
    """429 — too many requests. `retry_after` is the server's suggested wait (seconds)."""

    def __init__(self, message: str, *, retry_after: int = 60, **kw):
        super().__init__(message, **kw)
        self.retry_after = retry_after


class FormaAPIError(FormaError):
    """Any other non-2xx response from the API (4xx/5xx)."""


# ── Actionable error message formatters ──────────────────────────────────────
# Every formatter returns a multi-line string that tells the developer:
#   1. What went wrong  2. The exact fix  3. Why it matters

_PII_FIX: dict = {
    "Aadhaar number":                    "Remove the 12-digit Aadhaar. Use a customer_id/token instead:\n  │    ✗  'Customer Aadhaar: 2341 1234 1236'\n  │    ✓  'Customer ID: CUST-00471 (Aadhaar verified)'",
    "Aadhaar number (Verhoeff-verified)":"Remove the Aadhaar (real check digit confirmed). Use a tokenised ref.",
    "Indian PAN":                        "Remove the PAN. Store it in your vault; pass only 'PAN verified: true'.",
    "GSTIN":                             "Remove the GSTIN. Reference invoice/order ID instead.",
    "UPI ID":                            "Remove the UPI VPA. Use a payment_token or order_id instead.",
    "Phone number":                      "Remove the phone number. Use a masked form (***43210) or customer_id.",
    "Email address":                     "Remove the email. Use a customer_id or opaque user reference.",
    "Visa card":                         "Remove the card number. Use last-4 digits or a PSP payment token.",
    "Mastercard":                        "Remove the card number. Use a PSP payment token.",
    "Amex":                              "Remove the card number. Use a PSP payment token.",
    "CVV":                               "Never send CVV to an LLM. Remove it — this is a PCI DSS requirement.",
    "Credit/Debit card":                 "Remove the card number. Use a PSP payment token.",
    "IBAN":                              "Remove the IBAN. Use an account alias or transaction ID.",
    "IFSC code":                         "Remove the IFSC. Use a bank alias or transaction ID.",
    "SSN":                               "Remove the SSN. Use a tokenised identity reference.",
    "GSTIN (checksum-verified)":         "Remove the GSTIN (real business verified). Use an invoice/order ID.",
}

_RULE_FIX: dict = {
    "pii_in_prompt": (
        "PII in LLM prompt",
        "Do not send raw personal data to the LLM.\n"
        "  │  Anonymise before passing to the model:\n"
        "  │    ✗  prompt = f'Aadhaar: {aadhaar}, approve loan'\n"
        "  │    ✓  prompt = f'Customer ID: {customer_id}, approve loan'"
    ),
    "pii_in_tool_args": (
        "PII in tool arguments",
        "Do not pass raw personal data as tool arguments.\n"
        "  │    ✗  verify_kyc(aadhaar='2341 1234 1236')\n"
        "  │    ✓  verify_kyc(customer_id='CUST-00471')"
    ),
    "unauthorized_tool": (
        "Unauthorized tool call",
        "This tool is not in authorized_actions for this agent.\n"
        "  │  Add it to tl.init() or tl.register():\n"
        "  │    tl.init(authorized_actions=['tool_name', 'other_tool'])\n"
        "  │    # or per-agent:\n"
        "  │    tl.register('agent', fn, authorized_actions=['tool_name'])"
    ),
    "kill_switch": (
        "Kill switch active",
        "This agent is frozen — all actions blocked until cleared.\n"
        "  │  To resume:\n"
        "  │    Dashboard → Agents → Kill Switch → Clear\n"
        "  │  Or:  DELETE /api/agents/{agent}/kill   X-API-Key: tl_live_..."
    ),
}


def fmt_compliance_violation(reason: str, rule_id: Optional[str], pii_type: Optional[str],
                              agent_name: Optional[str], prompt_snippet: Optional[str],
                              enforce_packs: list) -> str:
    agent = f"'{agent_name}'" if agent_name else "your agent"
    # Find the right fix hint
    rk = rule_id or ""
    hint_key = next((k for k in _RULE_FIX if rk.startswith(k) or rk == k), None)
    if hint_key:
        rule_label, fix = _RULE_FIX[hint_key]
    elif pii_type:
        rule_label = f"PII detected: {pii_type}"
        fix = _PII_FIX.get(pii_type, f"Remove {pii_type} from prompt/args and use a safe reference.")
    elif "threat" in rk.lower():
        cat = rk.replace("threat:", "").replace("_", " ").title()
        rule_label = f"Threat detected: {cat}"
        fix = ("This prompt matches an attack pattern.\n"
               "  │  Check for: ignore/override instructions, system prompt leaks,\n"
               "  │  roleplay-switching, credential extraction, approval bypass.")
    else:
        rule_label = "Policy rule matched"
        fix = reason
    snip = f"\n  │  Prompt: \"{prompt_snippet[:70]}{'...' if prompt_snippet and len(prompt_snippet)>70 else ''}\"" if prompt_snippet else ""
    packs = f"\n  │  Active packs: {', '.join(enforce_packs)}" if enforce_packs else ""
    return (
        f"\n\033[31m  [FORMAAI Gate] BLOCKED — {rule_label}\033[0m\n"
        f"  Agent: {agent}  |  Rule: {rule_id or 'gate'}{snip}{packs}\n\n"
        f"  ┌─ What happened ───────────────────────────────────────────┐\n"
        f"  │  {reason[:72]}\n"
        f"  └──────────────────────────────────────────────────────────┘\n\n"
        f"  ┌─ Fix ─────────────────────────────────────────────────────┐\n"
        f"  │  {fix}\n"
        f"  └──────────────────────────────────────────────────────────┘\n\n"
        f"  This block is in your FORMA audit trail → formaai.in/dashboard\n"
    )


def fmt_no_key() -> str:
    return (
        "\n\033[33m  [FORMAAI] No API key — running without enforcement.\033[0m\n\n"
        "  ┌─ Fix (pick one) ──────────────────────────────────────────┐\n"
        "  │  A) Pass directly:  tl.init(api_key='tl_live_...')        │\n"
        "  │  B) Env var:        export FORMA_API_KEY='tl_live_...'    │\n"
        "  │  C) One-time setup: forma setup  (saves to ~/.forma/)     │\n"
        "  │                                                            │\n"
        "  │  Get your key: https://formaai.in/settings                │\n"
        "  └──────────────────────────────────────────────────────────┘\n"
    )


def fmt_invalid_packs(invalid: list, valid_packs: list, caller: str) -> str:
    def closest(name: str) -> Optional[str]:
        best, best_score = None, 0
        for v in valid_packs:
            shared = sum(1 for c in name if c in v)
            if shared > best_score: best, best_score = v, shared
        return best
    typo_hints = "\n  │  ".join(
        f"✗ '{p}' → did you mean '{closest(p)}'?" if closest(p) else f"✗ '{p}' (not a valid pack)"
        for p in invalid)
    return (
        f"\n\033[31m  [FORMAAI] {caller}: Unknown pack(s): {invalid}\033[0m\n\n"
        f"  ┌─ Fix ─────────────────────────────────────────────────────┐\n"
        f"  │  {typo_hints}\n"
        f"  │                                                            │\n"
        f"  │  Valid packs:  ai_safety · dpdp · rbi_ml_risk · pci_dss  │\n"
        f"  │               hipaa · eu_ai_act · gdpr · iso42001 · soc2  │\n"
        f"  │                                                            │\n"
        f"  │  Or use a preset:  tl.init(preset='india_fintech')        │\n"
        f"  └──────────────────────────────────────────────────────────┘\n"
    )


def fmt_invalid_risk_level(value: str, caller: str) -> str:
    return (
        f"\n\033[31m  [FORMAAI] {caller}: Invalid risk_level='{value}'\033[0m\n\n"
        f"  ┌─ Fix ─────────────────────────────────────────────────────┐\n"
        f"  │  Valid values (uppercase):                                 │\n"
        f"  │    'LOW'       internal tools, analytics                  │\n"
        f"  │    'MEDIUM'    default — general purpose agents           │\n"
        f"  │    'HIGH'      credit / KYC / loan decisions              │\n"
        f"  │    'CRITICAL'  payments / fund transfers                  │\n"
        f"  │                                                            │\n"
        f"  │  Example:  tl.init(risk_level='HIGH')                     │\n"
        f"  └──────────────────────────────────────────────────────────┘\n"
    )


def fmt_kill_switch(agent_name: str, reason: Optional[str] = None) -> str:
    return (
        f"\n\033[31m  [FORMAAI] Kill switch ACTIVE — '{agent_name}' is frozen.\033[0m\n"
        f"  {('Reason: ' + reason) if reason else ''}\n\n"
        f"  ┌─ How to resume ───────────────────────────────────────────┐\n"
        f"  │  Dashboard → Agents → '{agent_name}' → Kill Switch → Clear │\n"
        f"  │  Or: DELETE /api/agents/{agent_name}/kill                 │\n"
        f"  └──────────────────────────────────────────────────────────┘\n"
    )


def fmt_approval_rejected(agent_name: str, reason: Optional[str] = None) -> str:
    return (
        f"\n\033[33m  [FORMAAI] Approval REJECTED for '{agent_name}'.\033[0m\n"
        f"  {('Reason: ' + reason) if reason else 'No reason given.'}\n\n"
        f"  ┌─ What to do ──────────────────────────────────────────────┐\n"
        f"  │  The action was NOT executed. Log this and inform the     │\n"
        f"  │  user. See full trail: formaai.in/dashboard → Approvals  │\n"
        f"  └──────────────────────────────────────────────────────────┘\n"
    )


def fmt_approval_timeout(agent_name: str, timeout_s: int) -> str:
    return (
        f"\n\033[33m  [FORMAAI] Approval timeout for '{agent_name}' after {timeout_s}s.\033[0m\n\n"
        f"  ┌─ Fix ─────────────────────────────────────────────────────┐\n"
        f"  │  Increase timeout: tl.init(approval_timeout=7200)  # 2h  │\n"
        f"  │  Or catch and handle: except ApprovalTimeoutError         │\n"
        f"  └──────────────────────────────────────────────────────────┘\n"
    )
