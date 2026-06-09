"""
provn — zero-config AI agent observability and control.

Usage::

    import provn
    provn.init(api_key="tl_live_xxx")

    # That's it. Every LLM call (OpenAI, Anthropic, LiteLLM, LangChain) is now:
    #   - captured as a real AgentRun (not just shadow events)
    #   - gate-checked before execution (compliance firewall)
    #   - kill-switch aware (global process-level kill watch)
    #   - cost + token tracked
    #   - drift detected server-side
    #   - compliance evaluated

Decorators still work identically and take precedence over ambient runs::

    @provn.agent(
        purpose="Customer support",
        risk_level="HIGH",
        kill_switch=True,
        compliance=["EU_AI_ACT"],
    )
    def support_agent(ticket: str) -> dict: ...
"""
from __future__ import annotations

import trustlayer as _tl
from trustlayer import (
    AgentRun,
    ApprovalRejectedError,
    ApprovalTimeoutError,
    ComplianceViolation,
    KillSwitchTriggered,
    PROVNClient,
    PROVNTracker,
    StepType,
    TraceStep,
    agent,
    generate_keypair,
    get_passport_header,
    get_public_key_pem,
    sign_run,
    track,
    verify_run,
)

__version__ = _tl.__version__


def init(
    api_key: "str | None" = None,
    api_url: "str | None" = None,
    agent_name: "str | None" = None,
    human_sponsor: "str | None" = None,
    kill_switch: bool = False,
    gate: bool = True,
    compliance: "list[str] | None" = None,
    auto_capture: bool = True,
    ambient_runs: bool = True,
) -> PROVNTracker:
    """
    Initialize PROVN with zero-config defaults.

    One call gives you full AI agent observability and governance::

        import provn
        provn.init(api_key="tl_live_xxx")

    After this, all LLM calls across OpenAI, Anthropic, LiteLLM, and LangChain
    are automatically captured, gate-checked, kill-switch aware, cost-tracked,
    and fed into drift detection and compliance evaluation — no decorators needed.

    Args:
        api_key:       Your PROVN API key (or set TRUSTLAYER_API_KEY env var).
        api_url:       PROVN backend URL (default: http://localhost:8001).
        agent_name:    Display name for auto-captured ambient runs. Defaults to
                       the basename of sys.argv[0].
        human_sponsor: Accountable human for compliance (e.g. "alice@company.com").
        kill_switch:   Start a global process-level kill-switch watcher. When an
                       operator triggers a kill for this agent, the next LLM call
                       raises KillSwitchTriggered before executing.
        gate:          Pre-check every auto-captured LLM call against the
                       compliance gate. Raises ComplianceViolation on a "block"
                       decision. Defaults to True.
        compliance:    Compliance frameworks to enforce, e.g.
                       ["EU_AI_ACT", "RBI_MRM", "DPDP"].
        auto_capture:  Monkey-patch all supported LLM libraries on init.
                       Defaults to True.
        ambient_runs:  Create real AgentRuns for undecorated LLM calls instead
                       of anonymous shadow events. Enables drift detection,
                       compliance evaluation, and cost reporting without any
                       decorators. Defaults to True.

    Returns:
        PROVNTracker instance. Useful if you want to use tracker.llm_call(),
        tracker.tool_call(), or @tracker.agent() alongside zero-config mode.
    """
    tracker = _tl.init(
        api_key=api_key,
        api_url=api_url,
        agent_name=agent_name,
        human_sponsor=human_sponsor,
        auto_capture=auto_capture,
        kill_switch=kill_switch,
        gate=gate,
        compliance=compliance,
        ambient_runs=ambient_runs,
    )
    return tracker


__all__ = [
    "init",
    "track",
    "agent",
    "get_passport_header",
    "PROVNTracker",
    "PROVNClient",
    "AgentRun",
    "TraceStep",
    "StepType",
    "KillSwitchTriggered",
    "ComplianceViolation",
    "ApprovalRejectedError",
    "ApprovalTimeoutError",
    "generate_keypair",
    "get_public_key_pem",
    "sign_run",
    "verify_run",
]
