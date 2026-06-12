"""
Core @track decorator — wraps any agent function and captures:
  - Every LLM call (auto via monkey-patch OR manual via llm_call())
  - Every tool call (via tool_call() context manager)
  - Full run metadata with human sponsor attribution
  - Cryptographic signature on completion (Ed25519 or HMAC-SHA256 fallback)
  - Optional: hard cost limit enforcement (max_cost_usd)
  - Optional: human approval workflow (require_approval)
  - Optional: kill switch via WebSocket push (<50ms) with HTTP polling fallback
  - Optional: multi-agent chain audit (chain_parent=run_id)
"""
import functools
import hashlib
import json
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional

from .client import PROVNClient
from .crypto import sign_run
from .models import AgentRun, RunStatus, StepType, TraceStep

_local = threading.local()


def _current_run() -> Optional[AgentRun]:
    return getattr(_local, "current_run", None)


def _set_current_run(run: Optional[AgentRun]) -> None:
    _local.current_run = run


def _hash_payload(data: Any) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode()
    ).hexdigest()


# ── Kill switch — WebSocket listener with HTTP polling fallback ────────────────

class _KillPoller:
    """
    Real-time kill switch listener.

    Strategy (in priority order):
      1. WebSocket  — connects to /ws/sdk/kills/{agent_id}, receives push in <50ms.
      2. HTTP poll  — fallback: polls /api/agents/{agent_id}/kill-status every 2s.

    Both paths set the same threading.Event so the agent wrapper behaves identically.
    """

    def __init__(self, agent_id: str, api_url: str, api_key: str):
        self.agent_id    = agent_id
        self.api_url     = api_url.rstrip("/")
        self.api_key     = api_key
        self._kill_event = threading.Event()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ws_available: Optional[bool] = None   # cached after first attempt

    def start(self):
        self._kill_event.clear()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def is_killed(self) -> bool:
        return self._kill_event.is_set()

    # ── internal ──────────────────────────────────────────────────────────────

    def _run(self):
        """Try WebSocket first; fall back to HTTP polling."""
        if self._ws_available is not False:
            try:
                self._ws_loop()
                return
            except Exception:
                self._ws_available = False
        self._poll_loop()

    def _ws_loop(self):
        """Real-time kill via WebSocket — latency <50ms."""
        import urllib.request
        try:
            import websocket  # websocket-client package
        except ImportError:
            raise RuntimeError("websocket-client not installed")

        # Resolve ws:// or wss:// from api_url
        ws_url = self.api_url.replace("http://", "ws://").replace("https://", "wss://")
        url = f"{ws_url}/ws/sdk/kills/{self.agent_id}?api_key={self.api_key}"

        ws = websocket.WebSocket()
        ws.connect(url, timeout=5)
        self._ws_available = True

        try:
            while not self._stop_event.is_set():
                ws.settimeout(1.0)
                try:
                    raw = ws.recv()
                    if raw:
                        data = json.loads(raw)
                        if data.get("event") in ("kill_triggered", "kill_active"):
                            self._kill_event.set()
                            return
                except Exception:
                    if self._stop_event.is_set():
                        return
        finally:
            try:
                ws.close()
            except Exception:
                pass

    def _poll_loop(self):
        """HTTP polling fallback — latency ~2s."""
        import urllib.request
        url = f"{self.api_url}/api/agents/{self.agent_id}/kill-status"
        while not self._stop_event.is_set():
            try:
                req = urllib.request.Request(
                    url,
                    headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read())
                    if data.get("kill_active"):
                        self._kill_event.set()
                        return
            except Exception:
                pass
            self._stop_event.wait(timeout=2)


class KillSwitchTriggered(Exception):
    """Raised inside a tracked function when a kill signal is received."""
    pass


class ComplianceViolation(Exception):
    """Raised when the compliance gate blocks an action before execution."""
    def __init__(self, reason: str, rule_id: Optional[str] = None):
        self.reason = reason
        self.rule_id = rule_id
        super().__init__(f"[PROVN Gate] Blocked: {reason}")


def _infer_app_name() -> str:
    """Return a best-effort application name for ambient run labelling."""
    import sys
    import os
    try:
        argv0 = sys.argv[0] if sys.argv else ""
        name = os.path.basename(argv0)
        return name.removesuffix(".py") if name else "ambient"
    except Exception:
        return "ambient"


# ── Passport registration ──────────────────────────────────────────────────────

def _register_passport_async(
    agent_id: str,
    purpose: str,
    authorized_actions: List[str],
    risk_level: str,
    human_sponsor: str,
    kill_switch_enabled: bool,
    compliance: List[str],
    drift_threshold: float,
    api_url: str,
    api_key: str,
):
    """Fire-and-forget passport registration — never blocks the agent."""
    import urllib.request
    try:
        payload = json.dumps({
            "purpose": purpose,
            "authorized_actions": authorized_actions,
            "risk_level": risk_level,
            "human_sponsor": human_sponsor,
            "kill_switch_enabled": kill_switch_enabled,
            "compliance_frameworks": compliance,
            "drift_threshold": drift_threshold,
            "expires_days": 90,
        }).encode()
        req = urllib.request.Request(
            url=f"{api_url.rstrip('/')}/api/passport/{agent_id}",
            data=payload,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # Never fail agent startup due to passport registration


class PROVNTracker:
    """
    Instantiate once and reuse, or use the module-level @track decorator
    which uses a default tracker configured from environment variables.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        agent_name: Optional[str] = None,
        agent_version: str = "1.0.0",
        human_sponsor: Optional[str] = None,
        auto_capture: bool = True,
    ):
        self.api_key = api_key or os.environ.get("TRUSTLAYER_API_KEY", "dev")
        self.api_url = (
            api_url
            or os.environ.get("FORMA_API_URL")
            or os.environ.get("TRUSTLAYER_API_URL")
            or "https://forma.2bd.net"
        )
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.human_sponsor = human_sponsor or os.environ.get("TRUSTLAYER_HUMAN_SPONSOR") or None
        self._client = PROVNClient(api_key=self.api_key, base_url=self.api_url)

        if auto_capture:
            try:
                from .auto import patch_all
                patch_all()
            except Exception:
                pass

    def _local_or_server_gate(
        self,
        agent_ref: str,
        *,
        action_type: str,
        prompt: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Gate an action: local cached policy when available (<1ms, decisions
        batch-reported to the audit trail), otherwise the server gate check.
        """
        try:
            from .gate_local import get_shared_cache
            cache = get_shared_cache()
            if cache:
                result = cache.check(
                    agent_ref, action_type=action_type,
                    prompt=prompt, tool_name=tool_name, tool_args=tool_args,
                )
                if result is not None:
                    return result
        except Exception:
            pass
        return self._client.gate_check(
            agent_id=agent_ref, action_type=action_type,
            prompt=prompt, tool_name=tool_name, tool_args=tool_args,
        )

    def require_approval(
        self,
        via: str = "forma",
        url: Optional[str] = None,
        timeout: int = 3600,
        poll_interval: int = 5,
        message: Optional[str] = None,
        when: Optional[Callable] = None,
        title: Optional[str] = None,
    ):
        """
        Human-in-the-loop: pause the agent until a human decides in the
        FORMA Approvals inbox.

            @tracker.track
            @tracker.require_approval(
                when=lambda result: result["amount"] > 1_000_000,
                message="Loan above ₹10L requires human review (RBI).",
            )
            def approve_loan(application): ...
        """
        from .approval import RequireApprovalDecorator
        return RequireApprovalDecorator(
            tracker=self,
            via=via,
            url=url,
            timeout=timeout,
            poll_interval=poll_interval,
            message=message,
            when=when,
            title=title,
        )

    def agent(
        self,
        func: Optional[Callable] = None,
        *,
        name: Optional[str] = None,
        version: Optional[str] = None,
        sponsor: Optional[str] = None,
        # Identity Passport params
        purpose: str = "General AI agent task",
        authorized_actions: Optional[List[str]] = None,
        risk_level: str = "MEDIUM",
        # Kill switch
        kill_switch: bool = False,
        # Chain audit
        chain_parent: Optional[str] = None,
        chain_id: Optional[str] = None,
        # Drift detection
        drift_threshold: float = 0.15,
        # Compliance
        compliance: Optional[List[str]] = None,
        # Cost governance
        max_cost_usd: Optional[float] = None,
        # Runtime enforcement — framework policy packs evaluated locally
        # before every LLM/tool call (<1ms, no network hop in the hot path)
        enforce: Optional[List[str]] = None,
    ):
        """
        Full-featured decorator with identity passport, kill switch, chain
        support, and runtime compliance enforcement.

            @tracker.agent(
                name="loan-approval",
                purpose="Loan application evaluation",
                risk_level="HIGH",
                kill_switch=True,
                enforce=["rbi_ml_risk", "dpdp"],   # blocks violations pre-execution
            )
            def approve_loan(application: dict) -> dict: ...
        """
        def decorator(fn: Callable) -> Callable:
            # ── Runtime enforcement: register policy + start local gate ──────
            if enforce:
                try:
                    from .gate_local import get_shared_cache
                    cache = get_shared_cache(self._client)
                    if cache:
                        cache.register(name or self.agent_name or fn.__name__, enforce)
                except Exception:
                    pass

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                agent_name    = name or self.agent_name or fn.__name__
                agent_version = version or self.agent_version
                human_sponsor = sponsor or self.human_sponsor
                run_id = str(uuid.uuid4())

                # Compute chain IDs
                effective_chain_id = chain_id or (str(uuid.uuid4()) if chain_parent else None)
                depth = 0
                if chain_parent and effective_chain_id:
                    # Infer depth from parent (simple: just count)
                    depth = 1  # caller should pass explicit chain_id for deeper chains

                # Hash inputs for chain integrity
                input_payload = {"args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()}}
                input_hash = _hash_payload(input_payload) if effective_chain_id else None

                run = AgentRun(
                    run_id=run_id,
                    agent_name=agent_name,
                    agent_version=agent_version,
                    human_sponsor=human_sponsor,
                    started_at=datetime.now(timezone.utc),
                    input_data=input_payload,
                    metadata={
                        "chain_id": effective_chain_id,
                        "parent_run_id": chain_parent,
                        "chain_depth": depth,
                        "input_hash": input_hash,
                        "risk_level": risk_level,
                        "purpose": purpose,
                        "enforce": list(enforce) if enforce else [],
                    },
                )
                _set_current_run(run)

                # ── Kill switch poller ────────────────────────────────────────
                poller: Optional[_KillPoller] = None
                agent_id_for_kill: Optional[str] = None
                if kill_switch:
                    # We need the agent_id — look it up by name (best effort)
                    # The poller will be started, and the agent_id resolved on first poll
                    # For now we use agent_name as a proxy; server matches by name + org
                    agent_id_for_kill = f"name:{agent_name}"  # server resolves by name
                    poller = _KillPoller(
                        agent_id=agent_id_for_kill,
                        api_url=self.api_url,
                        api_key=self.api_key,
                    )
                    poller.start()

                try:
                    result = fn(*args, **kwargs)
                    if poller and poller.is_killed():
                        raise KillSwitchTriggered(f"Agent '{agent_name}' received kill signal")
                    run.status = RunStatus.SUCCESS
                    run.output_data = result
                    # Hash output for chain linking
                    if effective_chain_id:
                        run.metadata["output_hash"] = _hash_payload(result)
                    return result
                except KillSwitchTriggered:
                    run.status = RunStatus.FAILED
                    run.error = "Killed by operator via kill switch"
                    raise
                except Exception as exc:
                    run.status = RunStatus.FAILED
                    run.error = str(exc)
                    raise
                finally:
                    if poller:
                        poller.stop()
                    run.ended_at = datetime.now(timezone.utc)
                    run.duration_ms = int(
                        (run.ended_at - run.started_at).total_seconds() * 1000
                    )
                    run.total_tokens = sum(
                        (s.prompt_tokens or 0) + (s.completion_tokens or 0)
                        for s in run.steps
                    )
                    run.total_cost_usd = sum(s.cost_usd or 0.0 for s in run.steps)

                    if max_cost_usd is not None and run.total_cost_usd > max_cost_usd:
                        run.status = RunStatus.FAILED
                        run.error = f"Cost limit exceeded: ${run.total_cost_usd:.4f} > ${max_cost_usd}"

                    run_dict = run.to_dict()
                    # Embed chain metadata into the run dict for backend
                    run_dict["metadata"] = run.metadata or {}
                    run.signature = sign_run(run_dict, secret_key=self.api_key)
                    _set_current_run(None)
                    self._client.send_run(run)

                    # Acknowledge kill if applicable
                    if poller and poller.is_killed() and agent_id_for_kill:
                        self._ack_kill_async(agent_id_for_kill, run_id)

            # Register passport asynchronously on first decoration (at import time)
            threading.Thread(
                target=_register_passport_async,
                args=(
                    fn.__name__,
                    purpose,
                    authorized_actions or [],
                    risk_level,
                    self.human_sponsor,
                    kill_switch,
                    compliance or [],
                    drift_threshold,
                    self.api_url,
                    self.api_key,
                ),
                daemon=True,
            ).start()

            return wrapper

        if func is not None:
            return decorator(func)
        return decorator

    def _ack_kill_async(self, agent_id: str, run_id: str):
        import urllib.request
        def _ack():
            try:
                payload = json.dumps({"run_id": run_id, "partial_logged": True}).encode()
                req = urllib.request.Request(
                    url=f"{self.api_url}/api/agents/{agent_id}/kill/ack",
                    data=payload,
                    headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass
        threading.Thread(target=_ack, daemon=True).start()

    def _configure_ambient(
        self,
        agent_name: Optional[str],
        compliance: Optional[List[str]],
        gate: bool,
        ambient_runs: bool,
    ) -> None:
        """
        Write ambient run settings into auto._ambient_config so that every
        auto-captured LLM call (without a decorator) creates a real AgentRun.
        Also resets the cached PROVNClient so it picks up the new credentials.
        """
        import trustlayer.auto as _auto
        _auto._ambient_client = None  # reset cached client on config change
        _auto._ambient_config.update({
            "enabled": ambient_runs,
            "agent_name": agent_name or self.agent_name or _infer_app_name(),
            "agent_version": self.agent_version,
            "human_sponsor": self.human_sponsor,
            "compliance": list(compliance) if compliance else [],
            "gate_enabled": gate,
            "api_key": self.api_key,
            "api_url": self.api_url,
        })

    def _start_global_kill_watch(self, agent_name: Optional[str] = None) -> None:
        """
        Start a process-level kill-switch watcher for the ambient agent.

        When an operator triggers a kill, the threading.Event stored in
        auto._ambient_config["kill_event"] is set, and _check_kill() raises
        KillSwitchTriggered before the next patched LLM call executes.
        """
        import trustlayer.auto as _auto
        name = agent_name or _auto._ambient_config.get("agent_name", "ambient")
        poller = _KillPoller(
            agent_id=f"name:{name}",
            api_url=self.api_url,
            api_key=self.api_key,
        )
        poller.start()
        _auto._ambient_config["kill_event"] = poller._kill_event
        self._global_kill_poller = poller  # keep reference so GC doesn't kill it

    def track(
        self,
        func: Optional[Callable] = None,
        *,
        name: Optional[str] = None,
        version: Optional[str] = None,
        sponsor: Optional[str] = None,
        max_cost_usd: Optional[float] = None,
        risk_class: Optional[str] = None,
    ):
        """
        Decorator. Usage:

            tracker = PROVNTracker(agent_name="my-agent", human_sponsor="alice@co.com")

            @tracker.track
            def run_agent(query: str): ...
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                agent_name = name or self.agent_name or fn.__name__
                agent_version = version or self.agent_version
                human_sponsor = sponsor or self.human_sponsor
                run_id = str(uuid.uuid4())

                run = AgentRun(
                    run_id=run_id,
                    agent_name=agent_name,
                    agent_version=agent_version,
                    human_sponsor=human_sponsor,
                    started_at=datetime.now(timezone.utc),
                    input_data={"args": args, "kwargs": kwargs},
                )
                if risk_class:
                    run.metadata = {"risk_class": risk_class}
                _set_current_run(run)

                try:
                    result = fn(*args, **kwargs)
                    run.status = RunStatus.SUCCESS
                    run.output_data = result
                    return result
                except Exception as exc:
                    run.status = RunStatus.FAILED
                    run.error = str(exc)
                    raise
                finally:
                    run.ended_at = datetime.now(timezone.utc)
                    run.duration_ms = int(
                        (run.ended_at - run.started_at).total_seconds() * 1000
                    )
                    run.total_tokens = sum(
                        (s.prompt_tokens or 0) + (s.completion_tokens or 0)
                        for s in run.steps
                    )
                    run.total_cost_usd = sum(s.cost_usd or 0.0 for s in run.steps)

                    if max_cost_usd is not None and run.total_cost_usd > max_cost_usd:
                        run.status = RunStatus.FAILED
                        run.error = f"Cost limit exceeded: ${run.total_cost_usd:.4f} > ${max_cost_usd}"

                    run_dict = run.to_dict()
                    run.signature = sign_run(run_dict, secret_key=self.api_key)
                    _set_current_run(None)
                    self._client.send_run(run)

            return wrapper

        if func is not None:
            return decorator(func)
        return decorator

    @contextmanager
    def llm_call(
        self,
        label: str,
        model: str,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        cost_usd: Optional[float] = None,
        prompt: Optional[str] = None,
        gate: bool = True,
    ) -> Generator[TraceStep, None, None]:
        """
        Context manager for a single LLM call.

        Args:
            gate: If True (default), run the compliance gate before yielding.
                  Set to False to skip the gate check for this call.
            prompt: The prompt text to check for PII (optional but recommended).
        """
        run = _current_run()

        # ── Pre-emptive compliance gate (local policy first, server fallback) ──
        if gate and run is not None:
            agent_id = getattr(run, "_agent_id", None) or run.agent_name
            gate_result = self._local_or_server_gate(
                agent_id, action_type="llm_call", prompt=prompt,
            )
            if gate_result.get("decision") == "block":
                raise ComplianceViolation(
                    reason=gate_result.get("reason", "Compliance gate blocked this LLM call."),
                    rule_id=gate_result.get("rule_id"),
                )

        step_number = len(run.steps) + 1 if run else 1
        step = TraceStep(
            step_number=step_number,
            step_type=StepType.LLM,
            label=label,
            started_at=datetime.now(timezone.utc),
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost_usd,
        )
        try:
            yield step
        except Exception as exc:
            step.status = "error"
            step.error = str(exc)
            raise
        finally:
            step.ended_at = datetime.now(timezone.utc)
            step.duration_ms = int(
                (step.ended_at - step.started_at).total_seconds() * 1000
            )
            if run:
                run.steps.append(step)

    @contextmanager
    def tool_call(
        self,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]] = None,
        gate: bool = True,
    ) -> Generator[TraceStep, None, None]:
        """
        Context manager for a single tool call.

        Args:
            gate: If True (default), run the compliance gate before yielding.
                  Set to False to skip the gate check for this call.
        """
        run = _current_run()

        # ── Pre-emptive compliance gate (local policy first, server fallback) ──
        if gate and run is not None:
            agent_id = getattr(run, "_agent_id", None) or run.agent_name
            gate_result = self._local_or_server_gate(
                agent_id, action_type="tool_call",
                tool_name=tool_name, tool_args=tool_args,
            )
            if gate_result.get("decision") == "block":
                raise ComplianceViolation(
                    reason=gate_result.get("reason", f"Compliance gate blocked tool '{tool_name}'."),
                    rule_id=gate_result.get("rule_id"),
                )

        step_number = len(run.steps) + 1 if run else 1
        step = TraceStep(
            step_number=step_number,
            step_type=StepType.TOOL,
            label=f"Tool: {tool_name}",
            started_at=datetime.now(timezone.utc),
            tool_name=tool_name,
            tool_args=tool_args or {},
        )
        try:
            yield step
        except Exception as exc:
            step.status = "error"
            step.error = str(exc)
            raise
        finally:
            step.ended_at = datetime.now(timezone.utc)
            step.duration_ms = int(
                (step.ended_at - step.started_at).total_seconds() * 1000
            )
            if run:
                run.steps.append(step)


# ── Module-level default tracker ─────────────────────────────────────────────

_default_tracker: Optional[PROVNTracker] = None


def _get_default_tracker() -> PROVNTracker:
    global _default_tracker
    if _default_tracker is None:
        _default_tracker = PROVNTracker()
    return _default_tracker


def track(
    func: Optional[Callable] = None,
    *,
    name: Optional[str] = None,
    version: str = "1.0.0",
    sponsor: Optional[str] = None,
):
    """
    Module-level @track decorator using environment variable configuration.

    Configure via env vars:
        TRUSTLAYER_API_KEY
        TRUSTLAYER_API_URL
        TRUSTLAYER_HUMAN_SPONSOR

    Usage:
        @track
        def my_agent(query: str): ...
    """
    return _get_default_tracker().track(func, name=name, version=version, sponsor=sponsor)


def agent(
    func: Optional[Callable] = None,
    *,
    name: Optional[str] = None,
    version: str = "1.0.0",
    sponsor: Optional[str] = None,
    purpose: str = "General AI agent task",
    authorized_actions: Optional[List[str]] = None,
    risk_level: str = "MEDIUM",
    kill_switch: bool = False,
    chain_parent: Optional[str] = None,
    chain_id: Optional[str] = None,
    drift_threshold: float = 0.15,
    compliance: Optional[List[str]] = None,
    max_cost_usd: Optional[float] = None,
    enforce: Optional[List[str]] = None,
):
    """
    Module-level @agent decorator — full governance stack with runtime
    enforcement.

        @tl.agent(
            name="loan-approval",
            purpose="Loan application evaluation",
            risk_level="HIGH",
            kill_switch=True,
            enforce=["rbi_ml_risk", "dpdp"],   # block violations pre-execution
        )
        def approve_loan(application: dict) -> dict: ...

    With enforce=[...], every LLM/tool call is checked against the framework
    policy packs locally (<1ms) BEFORE it executes. Violations raise
    ComplianceViolation and appear as blocked events in the audit trail.
    """
    return _get_default_tracker().agent(
        func,
        name=name, version=version, sponsor=sponsor,
        purpose=purpose, authorized_actions=authorized_actions,
        risk_level=risk_level, kill_switch=kill_switch,
        chain_parent=chain_parent, chain_id=chain_id,
        drift_threshold=drift_threshold, compliance=compliance,
        max_cost_usd=max_cost_usd, enforce=enforce,
    )
