from .tracker import track, agent, PROVNTracker, KillSwitchTriggered, ComplianceViolation
from .client import PROVNClient
from .models import AgentRun, TraceStep, StepType
from .approval import ApprovalRejectedError, ApprovalTimeoutError
from .crypto import generate_keypair, get_public_key_pem, sign_run, verify_run

__version__ = "0.6.0"


def init(
    api_key: "str | None" = None,
    api_url: "str | None" = None,
    agent_name: "str | None" = None,
    human_sponsor: "str | None" = None,
    auto_capture: bool = True,
    kill_switch: bool = False,
    gate: bool = True,
    compliance: "list[str] | None" = None,
    ambient_runs: bool = True,
    enforce: "list[str] | None" = None,
) -> PROVNTracker:
    """
    Initialize FORMA with zero-config defaults.

    Sets the module-level default tracker used by @track and @agent.
    Call this once at the top of your application.

        import trustlayer as tl

        tl.init(api_key="tl_live_...", enforce=["dpdp"])

        # Every LLM call is now ENFORCED: PII, prompt injection, and policy
        # violations are blocked BEFORE the call executes — and every
        # decision lands in the FORMA audit trail. No decorators needed.

        # Or with full per-agent governance:
        @tl.agent(
            purpose="Loan application evaluation",
            risk_level="HIGH",
            kill_switch=True,
            enforce=["rbi_ml_risk", "dpdp"],
        )
        def approve_loan(application: dict): ...

    Args:
        api_key:       FORMA API key (or FORMA_API_KEY env var).
        api_url:       FORMA backend URL.
        agent_name:    Display name for ambient auto-captured runs.
        human_sponsor: Accountable human for compliance records.
        auto_capture:  Monkey-patch OpenAI/Anthropic/LiteLLM/LangChain. Default True.
        kill_switch:   Start a global process-level kill-switch watcher.
        gate:          Pre-check every auto-captured LLM call via compliance gate.
        compliance:    Compliance frameworks, e.g. ["EU_AI_ACT", "RBI_MRM"].
        ambient_runs:  Create real AgentRuns for undecorated LLM calls. Default True.
        enforce:       Framework policy packs enforced locally on every call
                       (e.g. ["dpdp", "rbi_ml_risk", "eu_ai_act"]). Violations
                       raise ComplianceViolation before the call executes.

    Returns the tracker instance if you need tracker.llm_call() etc.
    """
    import trustlayer.tracker as _mod

    tracker = PROVNTracker(
        api_key=api_key,
        api_url=api_url,
        agent_name=agent_name,
        human_sponsor=human_sponsor,
        auto_capture=auto_capture,
    )
    _mod._default_tracker = tracker

    tracker._configure_ambient(
        agent_name=agent_name,
        compliance=compliance,
        gate=gate,
        ambient_runs=ambient_runs,
    )

    if enforce:
        try:
            from .gate_local import get_shared_cache
            cache = get_shared_cache(tracker._client)
            if cache:
                import trustlayer.auto as _auto
                cache.register(_auto._ambient_config["agent_name"], list(enforce))
        except Exception:
            pass  # never fail init due to enforcement setup

    if kill_switch:
        try:
            tracker._start_global_kill_watch(agent_name=agent_name)
        except Exception:
            pass  # never fail init due to kill-switch setup

    return tracker


def require_approval(
    via: str = "forma",
    url: "str | None" = None,
    timeout: int = 3600,
    poll_interval: int = 5,
    message: "str | None" = None,
    when=None,
    title: "str | None" = None,
):
    """
    Module-level @require_approval — pause the agent until a human decides
    in the FORMA Approvals inbox (dashboard → Approvals).

        @tl.track
        @tl.require_approval(
            when=lambda result: result["amount"] > 1_000_000,
            message="Loan above ₹10L requires human review (RBI).",
        )
        def approve_loan(application): ...
    """
    import trustlayer.tracker as _mod
    return _mod._get_default_tracker().require_approval(
        via=via, url=url, timeout=timeout, poll_interval=poll_interval,
        message=message, when=when, title=title,
    )


def get_passport_header(agent_name: "str | None" = None) -> dict:
    """
    Returns the X-PROVN-Passport HTTP header for inter-agent trust.

    Use this when your agent calls another company's API that supports
    the PROVN Inter-Agent Trust Protocol.

    Example:
        headers = tl.get_passport_header(agent_name="loan-approval-agent")
        response = requests.post("https://api.partner.com/process",
                                 headers=headers, json=payload)

    The receiving API can verify your agent at:
        GET /agent-trust/verify/{passport_id}
    """
    import trustlayer.tracker as _mod
    tracker = _mod._get_default_tracker()
    try:
        import urllib.request, json as _json
        url = f"{tracker.api_url.rstrip('/')}/agent-trust/my-passport"
        req = urllib.request.Request(
            url,
            headers={"X-API-Key": tracker.api_key},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read())
            agents = data.get("agents", [])
            if agent_name:
                agents = [a for a in agents if a.get("agent_name") == agent_name]
            if agents:
                return {"X-PROVN-Passport": agents[0]["passport_id"]}
    except Exception:
        pass
    return {}


__all__ = [
    "track",
    "agent",
    "init",
    "require_approval",
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
