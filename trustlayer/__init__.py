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
) -> PROVNTracker:
    """
    Initialize PROVN with zero-config defaults.

    Sets the module-level default tracker used by @track and @agent.
    Call this once at the top of your application.

        import trustlayer as tl

        tl.init(api_key="tl_live_...", human_sponsor="you@company.com")

        # Zero-config: all LLM calls captured, gate-checked, kill-switch aware
        # No decorators needed.

        # Or with full governance:
        @tl.agent(
            purpose="Customer support classification",
            authorized_actions=["read_ticket", "send_reply"],
            risk_level="MEDIUM",
            kill_switch=True,
        )
        def support_agent(ticket: str): ...

    Args:
        api_key:       PROVN API key (or TRUSTLAYER_API_KEY env var).
        api_url:       PROVN backend URL (default http://localhost:8001).
        agent_name:    Display name for ambient auto-captured runs.
        human_sponsor: Accountable human for compliance records.
        auto_capture:  Monkey-patch OpenAI/Anthropic/LiteLLM/LangChain. Default True.
        kill_switch:   Start a global process-level kill-switch watcher.
        gate:          Pre-check every auto-captured LLM call via compliance gate.
        compliance:    Compliance frameworks, e.g. ["EU_AI_ACT", "RBI_MRM"].
        ambient_runs:  Create real AgentRuns for undecorated LLM calls. Default True.

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

    if kill_switch:
        try:
            tracker._start_global_kill_watch(agent_name=agent_name)
        except Exception:
            pass  # never fail init due to kill-switch setup

    return tracker


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
