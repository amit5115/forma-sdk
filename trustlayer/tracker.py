"""
Core tracking engine. Configured via tl.init() and scoped via tl.using();
there are no decorators. Captures:
  - Every LLM call (auto via monkey-patch OR manual via llm_call())
  - Every tool call (via tool_call() context manager)
  - Full run metadata with human sponsor attribution
  - Cryptographic signature on completion (Ed25519 or HMAC-SHA256 fallback)
  - Optional: hard cost limit enforcement (max_cost_usd)
  - Optional: human approval workflow (require_approval_when=)
  - Optional: kill switch via WebSocket push (<50ms) with HTTP polling fallback
  - Optional: multi-agent chain audit (chain_parent=run_id)
"""
import asyncio
import contextvars
import functools
import inspect
import logging
import json
import os
import sys
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

from .client import FormaClient
from .crypto import sign_run
from .models import AgentRun, RunStatus, StepType, TraceStep


def _forma_config() -> dict:
    """Read ~/.forma/config.json (written by `forma setup`) for zero-config init.

    Lets a non-technical user run `forma setup` once and then have a bare
    ``tl.init()`` (no api_key, no enforce) pick up the saved key + preset.
    Never raises — returns {} on any error or missing file.
    """
    try:
        path = os.path.join(os.path.expanduser("~"), ".forma", "config.json")
        if os.path.exists(path):
            with open(path) as fh:
                return json.loads(fh.read() or "{}")
    except Exception:
        pass
    return {}

# ── Context-local state (thread-safe AND asyncio-safe) ───────────────────────
# We use contextvars (not threading.local) so attribution stays correct when
# 20+ agents run concurrently across threads OR asyncio tasks. asyncio copies
# the context per-task, and worker threads start with an empty context, so each
# concurrent unit of work resolves its own current run + scope stack.
_current_run_var: "contextvars.ContextVar[Optional[AgentRun]]" = contextvars.ContextVar(
    "forma_current_run", default=None
)
_scope_stack_var: "contextvars.ContextVar[Tuple[Dict[str, Any], ...]]" = contextvars.ContextVar(
    "forma_scope_stack", default=()
)


def _current_run() -> Optional[AgentRun]:
    return _current_run_var.get()


def _set_current_run(run: Optional[AgentRun]) -> None:
    # Ambient (auto-capture) set-and-leave: persists for the rest of the
    # current context, mirroring the old per-thread behaviour.
    _current_run_var.set(run)


# ── tl.using(...) scope stack ────────────────────────────────────────────────
# Decorator-free multi-agent: `with tl.using("name", ...)` (or the @tl.using
# decorator) pushes a per-context scope (a discrete run + per-scope
# enforce/approval/governance config) that the auto-capture wrappers resolve
# over the process-wide init defaults. Push/pop use contextvars tokens so the
# stack is restored exactly, even under concurrency.

def _scope_stack() -> list:
    # Read-only snapshot for external consumers (auto.py reads via _current_scope).
    return list(_scope_stack_var.get())


def _current_scope() -> Optional[Dict[str, Any]]:
    stack = _scope_stack_var.get()
    return stack[-1] if stack else None


def _push_run(run: Optional[AgentRun]):
    return _current_run_var.set(run)


def _pop_run(token) -> None:
    _current_run_var.reset(token)


def _push_scope(scope: Dict[str, Any]):
    return _scope_stack_var.set(_scope_stack_var.get() + (scope,))


def _pop_scope(token) -> None:
    _scope_stack_var.reset(token)


class _UsingHandle:
    """What ``tl.using(...)`` / ``tracker.using(...)`` returns.

    The same object works three ways, so business code never changes shape:

    * **context manager** — ``with tl.using("agent"): ...``
    * **sync decorator** — ``@tl.using("agent")`` above a regular function
    * **async decorator** — ``@tl.using("agent")`` above an ``async def`` (the
      governed scope spans the *awaited* execution, not just coroutine creation)

    Each enter / each decorated call creates a fresh governed run, so a single
    handle is safely reusable and concurrency-correct (contextvars-backed).
    """

    __slots__ = ("_tracker", "_name", "_kwargs", "_cm")

    def __init__(self, tracker: "FormaTracker", name: str, kwargs: Dict[str, Any]):
        self._tracker = tracker
        self._name = name
        self._kwargs = kwargs
        self._cm = None

    def _new_cm(self):
        return self._tracker._using_cm(self._name, **self._kwargs)

    # context-manager protocol
    def __enter__(self):
        self._cm = self._new_cm()
        return self._cm.__enter__()

    def __exit__(self, *exc_info):
        return self._cm.__exit__(*exc_info)

    # decorator protocol (sync + async aware)
    def __call__(self, fn: Callable) -> Callable:
        name = self._name
        enforce = self._kwargs.get("enforce")

        tracker_ref = self._tracker

        # Register packs once at wrapper-setup time, not on every call.
        # If the cache doesn't exist yet (init() had no enforce=) we defer
        # registration to the first call, then cache the result so subsequent
        # calls skip the register() overhead entirely.
        _gate_cache_ref: list = [None]   # list so the closure can rebind it
        _gate_registered = [False]

        authorized_actions = self._kwargs.get("authorized_actions")

        if enforce:
            try:
                from .gate_local import get_shared_cache
                c = get_shared_cache(tracker_ref._client)
                if c is not None:
                    c.register(name, list(enforce),
                               authorized_actions=authorized_actions)
                    _gate_cache_ref[0] = c
                    _gate_registered[0] = True
            except Exception:
                pass

        # Register identity passport ONCE at setup time (not on every call).
        # _using_cm previously called _register_passport on every invocation of
        # the governed function — at 1000 calls/min this spawned 1000 background
        # HTTP threads/min. Moving it here means it runs exactly once per
        # tl.register() / agents= entry, regardless of call volume.
        _passport_kwargs = self._kwargs
        _purpose       = _passport_kwargs.get("purpose")
        _authz         = _passport_kwargs.get("authorized_actions")
        _risk          = _passport_kwargs.get("risk_level", "MEDIUM")
        _compliance    = _passport_kwargs.get("compliance")
        _kill          = _passport_kwargs.get("kill_switch", False)
        _drift         = _passport_kwargs.get("drift_threshold", 0.15)
        if _purpose or _authz or _kill or _risk != "MEDIUM":
            try:
                tracker_ref._register_passport(
                    name,
                    purpose=_purpose or "General AI agent task",
                    authorized_actions=_authz,
                    risk_level=_risk,
                    compliance=_compliance,
                    kill_switch=_kill,
                    drift_threshold=_drift,
                )
            except Exception:
                pass

        def _gate_check_inputs(*args, **kwargs) -> None:
            """Block PII/injection in function arguments before execution."""
            if not enforce:
                return
            # Collect all string values one level deep
            strings: list = []
            for a in args:
                if isinstance(a, str):
                    strings.append(a)
                elif isinstance(a, dict):
                    strings.extend(v for v in a.values() if isinstance(v, str))
            for v in kwargs.values():
                if isinstance(v, str):
                    strings.append(v)
                elif isinstance(v, dict):
                    strings.extend(vv for vv in v.values() if isinstance(vv, str))
            if not strings:
                return
            combined = " ".join(strings)
            try:
                from .gate_local import get_shared_cache
                cache = _gate_cache_ref[0]
                if cache is None:
                    # First call after deferred init — create + register now
                    cache = get_shared_cache(tracker_ref._client)
                    if cache is None:
                        return
                    cache.register(name, list(enforce),
                                   authorized_actions=authorized_actions)
                    _gate_cache_ref[0] = cache
                result = cache.check(name, action_type="llm_call", prompt=combined)
                if result.get("decision") == "block":
                    from .errors import fmt_compliance_violation
                    _snip = combined[:120] if combined else None
                    _pii = result.get("reason","").split("PII detected: ")
                    _pii_type = _pii[1].split(".")[0] if len(_pii) > 1 else None
                    raise ComplianceViolation(
                        fmt_compliance_violation(
                            reason=result.get("reason", "Policy violation"),
                            rule_id=result.get("rule_id"),
                            pii_type=_pii_type,
                            agent_name=name,
                            prompt_snippet=_snip,
                            enforce_packs=list(enforce or []),
                        )
                    )
            except ComplianceViolation:
                raise
            except Exception:
                pass  # gate check failure → fail open (non-blocking)

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def _async_wrapper(*args, **kwargs):
                _gate_check_inputs(*args, **kwargs)
                with self._new_cm():
                    return await fn(*args, **kwargs)

            return _async_wrapper

        @functools.wraps(fn)
        def _sync_wrapper(*args, **kwargs):
            _gate_check_inputs(*args, **kwargs)
            with self._new_cm():
                return fn(*args, **kwargs)

        return _sync_wrapper


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
            except Exception as _exc:
                logging.getLogger(__name__).debug("suppressed exception: %s", _exc)

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
            except Exception as _exc:
                logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
            self._stop_event.wait(timeout=2)


class KillSwitchTriggered(Exception):
    """Raised inside a tracked function when a kill signal is received."""
    pass


class ComplianceViolation(Exception):
    """Raised when the compliance gate blocks an action before execution."""
    def __init__(self, reason: str, rule_id: Optional[str] = None):
        self.reason = reason
        self.rule_id = rule_id
        super().__init__(f"[FORMA Gate] Blocked: {reason}")


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


class FormaTracker:
    """
    Instantiate via tl.init() (which configures and returns a process-wide
    tracker) and scope per-agent work with tl.using(). Manual instrumentation
    is available via llm_call() / tool_call() inside a using() block.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        agent_name: Optional[str] = None,
        agent_version: str = "1.0.0",
        human_sponsor: Optional[str] = None,
        auto_capture: bool = True,
        timeout: int = 10,
        max_retries: int = 2,
        fail_closed: bool = False,
    ):
        _cfg = _forma_config()
        resolved_key = (
            api_key
            or os.environ.get("FORMAAI_API_KEY")
            or os.environ.get("FORMA_API_KEY")
            or os.environ.get("TRUSTLAYER_API_KEY")
            or _cfg.get("api_key")
        )
        if not resolved_key:
            import warnings
            from .errors import fmt_no_key
            warnings.warn(fmt_no_key(), stacklevel=4)
        self.api_key = resolved_key or "dev"
        self.api_url = (
            api_url
            or os.environ.get("FORMAAI_API_URL")
            or os.environ.get("FORMA_API_URL")
            or os.environ.get("TRUSTLAYER_API_URL")
            or _cfg.get("api_url")
            or "https://api.formaai.in"
        )
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.human_sponsor = (
            human_sponsor
            or os.environ.get("FORMA_HUMAN_SPONSOR")
            or os.environ.get("TRUSTLAYER_HUMAN_SPONSOR")
            or None
        )
        self._timeout = timeout
        self._max_retries = max_retries
        self._fail_closed = fail_closed
        # Guards the per-agent kill-poller registry so concurrent first-calls to
        # a kill_switch=True agent don't each spawn a duplicate poller thread.
        self._kill_lock = threading.Lock()
        self._agent_kill_pollers: Dict[str, "_KillPoller"] = {}
        self._global_kill_poller: Optional["_KillPoller"] = None
        self._client = FormaClient(
            api_key=self.api_key, base_url=self.api_url,
            timeout=timeout, max_retries=max_retries, fail_closed=fail_closed,
        )

        if auto_capture:
            try:
                from .auto import patch_all
                patch_all()
            except Exception as _exc:
                logging.getLogger(__name__).debug("suppressed exception: %s", _exc)

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
        except Exception as _exc:
            logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
        return self._client.gate_check(
            agent_id=agent_ref, action_type=action_type,
            prompt=prompt, tool_name=tool_name, tool_args=tool_args,
        )

    # ── Run lifecycle helper (shared by tl.using + ambient flush) ───────────
    def _finalize_and_send(
        self, run: AgentRun, *, max_cost_usd: Optional[float] = None,
    ) -> None:
        """Finalize timing/cost, sign, and send a run. Idempotent per run."""
        if getattr(run, "_forma_flushed", False):
            return
        run._forma_flushed = True  # type: ignore[attr-defined]
        if run.ended_at is None:
            run.ended_at = datetime.now(timezone.utc)
        if run.started_at and run.ended_at:
            run.duration_ms = int(
                (run.ended_at - run.started_at).total_seconds() * 1000
            )
        run.total_tokens = sum(
            (s.prompt_tokens or 0) + (s.completion_tokens or 0) for s in run.steps
        )
        run.total_cost_usd = sum(s.cost_usd or 0.0 for s in run.steps)
        if max_cost_usd is not None and run.total_cost_usd > max_cost_usd:
            run.status = RunStatus.FAILED
            run.error = f"Cost limit exceeded: ${run.total_cost_usd:.4f} > ${max_cost_usd}"
        if run.status == RunStatus.RUNNING:
            run.status = RunStatus.SUCCESS
        run_dict = run.to_dict()
        run.signature = sign_run(run_dict, secret_key=self.api_key)
        self._client.send_run(run)

    def _register_passport(
        self,
        name: str,
        *,
        purpose: str = "General AI agent task",
        authorized_actions: Optional[List[str]] = None,
        risk_level: str = "MEDIUM",
        compliance: Optional[List[str]] = None,
        drift_threshold: float = 0.15,
        kill_switch: bool = False,
    ) -> None:
        """Best-effort, fire-and-forget identity-passport registration."""
        threading.Thread(
            target=_register_passport_async,
            args=(
                name, purpose, authorized_actions or [], risk_level,
                self.human_sponsor, kill_switch, compliance or [],
                drift_threshold, self.api_url, self.api_key,
            ),
            daemon=True,
        ).start()

    def using(
        self,
        name: str,
        *,
        enforce: Optional[List[str]] = None,
        compliance: Optional[List[str]] = None,
        risk_level: str = "MEDIUM",
        human_sponsor: Optional[str] = None,
        purpose: Optional[str] = None,
        authorized_actions: Optional[List[str]] = None,
        max_cost_usd: Optional[float] = None,
        require_approval_when: Optional[Callable[[Dict[str, Any]], bool]] = None,
        approval_message: Optional[str] = None,
        approval_title: Optional[str] = None,
        approval_timeout: int = 3600,
        approval_poll_interval: int = 5,
        approval_via: str = "forma",
        version: Optional[str] = None,
        kill_switch: bool = False,
        drift_threshold: float = 0.15,
    ) -> "_UsingHandle":
        """
        Internal multi-agent scope helper that powers ``tl.register()`` and
        ``tl.init(agents={...})``. Every auto-captured LLM/tool call inside the
        scope is attributed to agent ``name`` with its own discrete, signed run
        and its own enforcement/approval/governance config.

        Not part of the public API surface (use ``tl.register`` / ``tl.init``).

        Validates kwargs eagerly (unknown keyword → ``TypeError``) so the
        documented argument list stays truthful.
        """
        return _UsingHandle(
            self,
            name,
            dict(
                enforce=enforce, compliance=compliance, risk_level=risk_level,
                human_sponsor=human_sponsor, purpose=purpose,
                authorized_actions=authorized_actions, max_cost_usd=max_cost_usd,
                require_approval_when=require_approval_when,
                approval_message=approval_message, approval_title=approval_title,
                approval_timeout=approval_timeout,
                approval_poll_interval=approval_poll_interval,
                approval_via=approval_via, version=version,
                kill_switch=kill_switch, drift_threshold=drift_threshold,
            ),
        )

    @contextmanager
    def _using_cm(
        self,
        name: str,
        *,
        enforce: Optional[List[str]] = None,
        compliance: Optional[List[str]] = None,
        risk_level: str = "MEDIUM",
        human_sponsor: Optional[str] = None,
        purpose: Optional[str] = None,
        authorized_actions: Optional[List[str]] = None,
        max_cost_usd: Optional[float] = None,
        require_approval_when: Optional[Callable[[Dict[str, Any]], bool]] = None,
        approval_message: Optional[str] = None,
        approval_title: Optional[str] = None,
        approval_timeout: int = 3600,
        approval_poll_interval: int = 5,
        approval_via: str = "forma",
        version: Optional[str] = None,
        kill_switch: bool = False,
        drift_threshold: float = 0.15,
    ) -> Generator[AgentRun, None, None]:
        """Internal generator that powers :meth:`using`. Pushes/pops a discrete
        governed run + scope using contextvars tokens so attribution is correct
        under threads and asyncio."""
        # Per-scope runtime enforcement (local gate).
        # Only register the policy once — subsequent calls with the same agent
        # name skip this to avoid redundant lock contention and thread spawns.
        if enforce:
            try:
                from .gate_local import get_shared_cache
                cache = get_shared_cache(self._client)
                if cache and cache.get(name) is None:
                    cache.register(name, list(enforce), authorized_actions=authorized_actions)
            except Exception as _exc:
                logging.getLogger(__name__).debug("suppressed exception: %s", _exc)

        run = AgentRun(
            run_id=str(uuid.uuid4()),
            agent_name=name,
            agent_version=version or self.agent_version,
            human_sponsor=human_sponsor or self.human_sponsor,
            started_at=datetime.now(timezone.utc),
            input_data={"source": "tl.using"},
            metadata={
                "risk_level": risk_level,
                "purpose": purpose,
                "enforce": list(enforce) if enforce else [],
                "compliance_frameworks": list(compliance) if compliance else [],
            },
        )
        scope = {
            "agent_name": name,
            "require_approval_when": require_approval_when,
            "approval": {
                "message": approval_message,
                "title": approval_title,
                "timeout": approval_timeout,
                "poll_interval": approval_poll_interval,
                "via": approval_via,
            },
            "max_cost_usd": max_cost_usd,
            "authorized_actions": authorized_actions,
        }
        # Per-agent kill switch: a dedicated poller per agent name, started once,
        # whose event is checked on every captured call made inside this scope.
        if kill_switch:
            scope["kill_event"] = self._ensure_agent_kill_watch(name)

        run_token = _push_run(run)
        scope_token = _push_scope(scope)

        # Passport registration is handled once at wrapper-setup time in
        # _UsingHandle.__call__ — do NOT call it here or it fires on every
        # function invocation (1000 calls/min → 1000 background threads/min).

        try:
            yield run
        except Exception as exc:
            run.status = RunStatus.FAILED
            run.error = str(exc)
            raise
        finally:
            _pop_scope(scope_token)
            _pop_run(run_token)
            self._finalize_and_send(run, max_cost_usd=max_cost_usd)

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
            except Exception as _exc:
                logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
        threading.Thread(target=_ack, daemon=True).start()

    def _configure_ambient(
        self,
        agent_name: Optional[str],
        compliance: Optional[List[str]],
        gate: bool,
        ambient_runs: bool,
        *,
        max_cost_usd: Optional[float] = None,
        authorized_actions: Optional[List[str]] = None,
        require_approval_when: Optional[Callable[[Dict[str, Any]], bool]] = None,
        approval_message: Optional[str] = None,
        approval_title: Optional[str] = None,
        approval_timeout: int = 3600,
        approval_poll_interval: int = 5,
        approval_via: str = "forma",
    ) -> None:
        """
        Write ambient run settings into auto._ambient_config so that every
        auto-captured LLM call (with no scope/decorator) creates a real
        AgentRun and is governed by the process-wide init() config. Also resets
        the cached FormaClient so it picks up the new credentials.
        """
        import trustlayer.auto as _auto
        _auto._ambient_client = None  # reset cached client on config change
        _auto._server_gate_cooldown_until = 0.0  # fresh init starts gate-healthy
        _auto._ambient_config.update({
            "enabled": ambient_runs,
            # Clear any kill_event left over from a previous init() call.
            # _start_global_kill_watch() (called after _configure_ambient) will
            # set a fresh event when kill_switch=True — without this reset, a
            # second tl.init(kill_switch=False) would leave the old event active.
            "kill_event": None,
            "agent_name": agent_name or self.agent_name or _infer_app_name(),
            "agent_version": self.agent_version,
            "human_sponsor": self.human_sponsor,
            "compliance": list(compliance) if compliance else [],
            "gate_enabled": gate,
            "api_key": self.api_key,
            "api_url": self.api_url,
            "timeout": self._timeout,
            "max_retries": self._max_retries,
            "fail_closed": self._fail_closed,
            "max_cost_usd": max_cost_usd,
            "authorized_actions": list(authorized_actions) if authorized_actions else None,
            "require_approval_when": require_approval_when,
            "approval": {
                "message": approval_message,
                "title": approval_title,
                "timeout": approval_timeout,
                "poll_interval": approval_poll_interval,
                "via": approval_via,
            },
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

    def _ensure_agent_kill_watch(self, name: str) -> "threading.Event":
        """
        Start (once) a per-agent kill-switch poller for ``name`` and return its
        kill event. The event is stored on the agent's scope so captured calls
        inside ``tl.register(name, ..., kill_switch=True)`` are halted the moment
        an operator triggers a kill for that agent.
        """
        # Get-or-create under the lock so concurrent first-calls don't each
        # start a duplicate poller thread for the same agent.
        with self._kill_lock:
            poller = self._agent_kill_pollers.get(name)
            if poller is None:
                poller = _KillPoller(
                    agent_id=f"name:{name}",
                    api_url=self.api_url,
                    api_key=self.api_key,
                )
                poller.start()
                self._agent_kill_pollers[name] = poller
        return poller._kill_event

    def shutdown(self) -> None:
        """
        Stop this tracker's background kill-switch pollers.

        Called on re-init (a second tl.init()) so the previous tracker's poller
        threads don't keep polling the API forever — otherwise every re-init in a
        notebook / dev hot-reload / worker re-import leaks a thread that hits
        /kill-status every 2s. Best-effort: never raises.
        """
        with self._kill_lock:
            pollers = list(self._agent_kill_pollers.values())
            self._agent_kill_pollers.clear()
        if self._global_kill_poller is not None:
            pollers.append(self._global_kill_poller)
            self._global_kill_poller = None
        for p in pollers:
            try:
                p.stop()
            except Exception as _exc:
                logging.getLogger(__name__).debug("poller stop failed: %s", _exc)

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
                from .errors import fmt_compliance_violation
                _reason = gate_result.get("reason","Compliance gate blocked this LLM call.")
                _pii = _reason.split("PII detected: ")
                _pii_type = _pii[1].split(".")[0] if len(_pii) > 1 else None
                raise ComplianceViolation(
                    fmt_compliance_violation(
                        reason=_reason,
                        rule_id=gate_result.get("rule_id"),
                        pii_type=_pii_type,
                        agent_name=getattr(run,"agent_name",None) if run else None,
                        prompt_snippet=prompt[:120] if prompt else None,
                        enforce_packs=[],
                    )
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

_default_tracker: Optional[FormaTracker] = None


def _get_default_tracker() -> FormaTracker:
    global _default_tracker
    if _default_tracker is None:
        _default_tracker = FormaTracker()
    return _default_tracker


def using(
    name: str,
    *,
    enforce: Optional[List[str]] = None,
    compliance: Optional[List[str]] = None,
    risk_level: str = "MEDIUM",
    human_sponsor: Optional[str] = None,
    purpose: Optional[str] = None,
    authorized_actions: Optional[List[str]] = None,
    max_cost_usd: Optional[float] = None,
    require_approval_when: Optional[Callable[[Dict[str, Any]], bool]] = None,
    approval_message: Optional[str] = None,
    approval_title: Optional[str] = None,
    approval_timeout: int = 3600,
    approval_poll_interval: int = 5,
    approval_via: str = "forma",
    version: Optional[str] = None,
    kill_switch: bool = False,
    drift_threshold: float = 0.15,
):
    """
    Internal multi-agent scope helper that powers ``tl.register()`` and
    ``tl.init(agents={...})``. Not part of the public API surface — call
    ``tl.register(name, fn, ...)`` (or pass ``agents={...}`` to ``tl.init``)
    instead.

    Every auto-captured LLM/tool call inside the scope is attributed to ``name``
    as its own discrete, signed run, with its own enforcement, approval, and
    governance config. Scopes may be nested.
    """
    return _get_default_tracker().using(
        name,
        enforce=enforce, compliance=compliance, risk_level=risk_level,
        human_sponsor=human_sponsor, purpose=purpose,
        authorized_actions=authorized_actions, max_cost_usd=max_cost_usd,
        require_approval_when=require_approval_when,
        approval_message=approval_message, approval_title=approval_title,
        approval_timeout=approval_timeout, approval_poll_interval=approval_poll_interval,
        approval_via=approval_via, version=version,
        kill_switch=kill_switch, drift_threshold=drift_threshold,
    )


def register(name: str, fn: Optional[Callable] = None, **cfg):
    """Bind an existing function to a FORMA agent — one of the SDK's two entry
    points (the other is :func:`init`).

    Governs an *existing* function **without touching its body** and without a
    decorator line. Every auto-captured LLM/tool call made while the function
    runs is attributed to ``name`` with its own discrete, signed run and its own
    enforce / approval / governance config.

        import trustlayer as tl
        from my_app import loan_screener, fraud_detector

        tl.init(api_key="tl_live_...")
        tl.register("loan-screener", loan_screener,
                    enforce=["rbi_ml_risk", "dpdp"], risk_level="HIGH",
                    kill_switch=True, max_cost_usd=5.0)
        tl.register("fraud-detector", fraud_detector, enforce=["dpdp"])

    ``register`` re-points the name in the function's defining module to the
    governed wrapper, so existing callers transparently get governance. It also
    works as a decorator::

        @tl.register("loan-screener", enforce=["rbi_ml_risk"])
        def loan_screener(application): ...

    When to use ``tl.register`` vs ``tl.init(agents={...})``:
      * ``tl.init(agents={...})`` — bulk-register when every agent function is
        importable at the single init() call (top of your entrypoint). Simplest.
      * ``tl.register(name, fn, ...)`` — when a function is imported/defined
        AFTER init(), when you want the decorator form ``@tl.register(...)``, or
        for conditional / dynamic registration.

    Accepts the **same full keyword set as** :func:`init`'s per-agent governance
    config: ``enforce, compliance, risk_level, human_sponsor, purpose,
    authorized_actions, max_cost_usd, require_approval_when, approval_message,
    approval_title, approval_timeout, approval_poll_interval, approval_via,
    version, kill_switch, drift_threshold`` (unknown keyword → ``TypeError``).
    Works for sync and ``async def`` targets.

    Caveat: like ``tl.init``, this must run before the target is *called*
    (top of your entrypoint). A pre-existing ``from mod import fn`` alias that
    was bound before ``register`` ran won't be intercepted — import the module
    and reference ``mod.fn`` so the re-point is visible to callers.
    """

    if not isinstance(name, str):
        raise TypeError(
            f"tl.register() first argument must be a string agent name, "
            f"got {type(name).__name__}. "
            f"Usage: tl.register('agent-name', fn, **cfg)"
        )

    # Validate all governance params eagerly — bad values should be caught at
    # registration time, not silently stored and crash at call time.
    try:
        from trustlayer import _validate_packs, _validate_governance_params
        _validate_packs(cfg.get("enforce"), cfg.get("compliance"),
                        caller=f"tl.register('{name}')")
        _validate_governance_params(
            cfg.get("risk_level", "MEDIUM"),
            cfg.get("require_approval_when"),
            cfg.get("approval_timeout", 3600),
            cfg.get("approval_poll_interval", 5),
            cfg.get("drift_threshold", 0.15),
            caller=f"tl.register('{name}')",
        )
    except ImportError:
        pass  # circular-import guard during package initialisation

    def _wrap(f: Callable) -> Callable:
        # using() validates kwargs (raises TypeError on unknown keys) and returns
        # an async-aware handle; calling it on f produces the governed wrapper.
        wrapped = using(name, **cfg)(f)
        fn_module = getattr(f, "__module__", None) or ""
        if fn_module != "builtins":
            mod = sys.modules.get(fn_module)
            if mod is not None and getattr(mod, getattr(f, "__name__", ""), None) is f:
                setattr(mod, f.__name__, wrapped)  # re-point name → governed wrapper
        return wrapped

    return _wrap(fn) if fn is not None else _wrap
