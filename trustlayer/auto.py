"""
Zero-Config Auto-Capture (v2)

Monkey-patches OpenAI, Anthropic, LiteLLM, and LangChain clients so that
every LLM call is automatically captured into the active FORMA run —
without the developer writing any tracking code.

Improvements over v1:
  - Robust class-level patching for OpenAI v1+ SDK (sync + async)
  - Async patching for Anthropic
  - LiteLLM sync + async patching
  - LangChain BaseLLM._generate / _agenerate hook (auto-detects langchain-core)
  - Shadow agent detection for all four providers
"""
from __future__ import annotations
import logging

import atexit
import functools
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    pass

# ── Pricing table (USD per 1K tokens) ────────────────────────────────────────
_PRICING: dict[str, dict[str, float]] = {
    "gpt-4o":             {"input": 0.005,   "output": 0.015},
    "gpt-4o-mini":        {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo":        {"input": 0.01,    "output": 0.03},
    "gpt-4":              {"input": 0.03,    "output": 0.06},
    "gpt-3.5-turbo":      {"input": 0.0005,  "output": 0.0015},
    "claude-3-5-sonnet":  {"input": 0.003,   "output": 0.015},
    "claude-3-5-haiku":   {"input": 0.0008,  "output": 0.004},
    "claude-3-opus":      {"input": 0.015,   "output": 0.075},
    "claude-3-sonnet":    {"input": 0.003,   "output": 0.015},
    "claude-3-haiku":     {"input": 0.00025, "output": 0.00125},
    "gemini-1.5-pro":     {"input": 0.00125, "output": 0.005},
    "gemini-1.5-flash":   {"input": 0.000075,"output": 0.0003},
}

_DEFAULT_COST = {"input": 0.002, "output": 0.002}
_patched = False

# ── Ambient run config (populated by FormaTracker._configure_ambient) ─────────

_ambient_config: dict = {
    "enabled": False,           # True once trustlayer.init() runs
    "agent_name": "ambient",    # display name for auto-captured runs
    "agent_version": "1.0.0",
    "human_sponsor": "unknown",
    "compliance": [],           # e.g. ["EU_AI_ACT", "RBI_MRM"]
    "gate_enabled": False,      # pre-call compliance gate check
    "kill_event": None,         # threading.Event set by global kill poller
    "api_key": "dev",
    "api_url": "https://api.formaai.in",
    "timeout": 10,              # transport: init(timeout=)
    "max_retries": 2,           # transport: init(max_retries=)
    "fail_closed": False,       # gate fail-closed: init(fail_closed=)
    "max_cost_usd": None,       # hard per-run cost cap (init(max_cost_usd=))
    "authorized_actions": None, # allowed tool names (init(authorized_actions=))
    # Human-in-the-loop: predicate ctx->bool evaluated before each captured call
    "require_approval_when": None,
    "approval": {               # approval config (init(approval_*=))
        "message": None, "title": None, "timeout": 3600,
        "poll_interval": 5, "via": "forma",
    },
}

_ambient_runs: list = []                                   # all pending ambient runs
_ambient_runs_lock = __import__("threading").Lock()
_atexit_registered = False
_ambient_client = None                                     # cached FormaClient

# Server-gate health (fail-open mode only): when the synchronous gate check can't
# reach the API, skip it for a short cooldown so a down/slow API doesn't add the
# gate timeout to EVERY LLM call. The local enforce=[...] path is unaffected.
_SERVER_GATE_COOLDOWN_SEC = 30.0
_server_gate_cooldown_until = 0.0


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    pricing = _DEFAULT_COST
    for key, price in _PRICING.items():
        if model.startswith(key):
            pricing = price
            break
    return round(
        (prompt_tokens * pricing["input"] + completion_tokens * pricing["output"]) / 1000,
        6,
    )


def _get_current_run():
    from trustlayer.tracker import _current_run
    return _current_run()


# ── Shadow event buffer ───────────────────────────────────────────────────────

_shadow_buffer: list = []
_shadow_lock = __import__("threading").Lock()
_shadow_flush_started = False


def _record_shadow_event(model: str, provider: str, prompt_tokens: int,
                         completion_tokens: int, est_cost_usd: float):
    import traceback, os
    caller_file = caller_func = caller_module = None
    for frame in traceback.extract_stack():
        fname = frame.filename
        if any(x in fname for x in ("trustlayer", "openai", "anthropic", "litellm", "langchain")):
            continue
        caller_file = os.path.basename(fname)
        caller_func = frame.name
        caller_module = fname.replace(os.sep, ".").rstrip(".py")
        break
    with _shadow_lock:
        _shadow_buffer.append({
            "model": model, "provider": provider,
            "caller_file": caller_file, "caller_func": caller_func,
            "caller_module": caller_module,
            "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
            "est_cost_usd": est_cost_usd,
        })


def _flush_shadow_events():
    import json, threading, urllib.request, os

    def _loop():
        while True:
            __import__("time").sleep(60)
            with _shadow_lock:
                events = list(_shadow_buffer)
                _shadow_buffer.clear()
            if not events:
                continue
            try:
                api_url = (os.environ.get("FORMAAI_API_URL") or os.environ.get("FORMA_API_URL") or os.environ.get("TRUSTLAYER_API_URL") or "https://api.formaai.in").rstrip("/")
                api_key = os.environ.get("FORMAAI_API_KEY") or os.environ.get("FORMA_API_KEY") or os.environ.get("TRUSTLAYER_API_KEY", "dev")
                payload = json.dumps({"events": events}).encode()
                req = urllib.request.Request(
                    url=f"{api_url}/api/shadow/events", data=payload,
                    headers={"X-API-Key": api_key, "Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)
            except Exception as _exc:
                logging.getLogger(__name__).debug("suppressed exception: %s", _exc)

    threading.Thread(target=_loop, daemon=True).start()


# ── Ambient run helpers ───────────────────────────────────────────────────────

def _get_ambient_client():
    """Return a cached FormaClient using the current ambient config."""
    global _ambient_client
    if _ambient_client is None:
        from trustlayer.client import FormaClient
        _ambient_client = FormaClient(
            api_key=_ambient_config["api_key"],
            base_url=_ambient_config["api_url"],
            timeout=_ambient_config.get("timeout", 10),
            max_retries=_ambient_config.get("max_retries", 2),
            fail_closed=_ambient_config.get("fail_closed", False),
        )
    return _ambient_client


def _register_atexit_flush():
    global _atexit_registered
    if not _atexit_registered:
        _atexit_registered = True
        atexit.register(_flush_all_ambient_runs)


def _ensure_ambient_run():
    """
    Create a per-thread ambient AgentRun if none exists and ambient mode is on.

    Called at the start of every patched LLM wrapper so that undecorated LLM
    calls accumulate steps on a real run instead of going to shadow events.
    The run is flushed to the API on process exit via an atexit handler.
    Returns the active run (existing or newly created), or None if disabled.
    """
    if not _ambient_config["enabled"]:
        return None
    from trustlayer.tracker import _current_run, _set_current_run
    run = _current_run()
    if run is not None:
        return run

    from trustlayer.models import AgentRun, RunStatus
    run = AgentRun(
        run_id=str(uuid.uuid4()),
        agent_name=_ambient_config["agent_name"],
        agent_version=_ambient_config["agent_version"],
        human_sponsor=_ambient_config.get("human_sponsor") or None,  # None → server auto-fills from account
        started_at=datetime.now(timezone.utc),
        input_data={"source": "auto_capture"},
        metadata={
            "compliance_frameworks": _ambient_config.get("compliance", []),
            "ambient": True,
        },
    )
    _set_current_run(run)
    with _ambient_runs_lock:
        _ambient_runs.append(run)
    _register_atexit_flush()
    return run


def _check_kill():
    """Raise KillSwitchTriggered if a kill event is set — per-agent scope first
    (tl.register(..., kill_switch=True)), then the process-wide ambient watch
    (tl.init(kill_switch=True))."""
    from trustlayer.tracker import _current_scope, KillSwitchTriggered

    scope = _current_scope()
    if scope:
        scope_event = scope.get("kill_event")
        if scope_event is not None and scope_event.is_set():
            raise KillSwitchTriggered(
                f"Kill switch triggered for agent '{scope.get('agent_name')}'"
            )

    kill_event = _ambient_config.get("kill_event")
    if kill_event is not None and kill_event.is_set():
        raise KillSwitchTriggered(
            f"Kill switch triggered for agent '{_ambient_config['agent_name']}'"
        )


_GATE_SCAN_CAP = 8000  # bound worst-case scan cost on pathologically large prompts


def _extract_prompt(kwargs: dict) -> "str | None":
    """Concatenate ALL developer-provided message text (system + user + tool
    results) so the gate sees PII / injection ANYWHERE in the request.

    Previously this returned only the LAST user message's first 500 chars, which
    silently let PII bypass the gate in three common shapes: PII in an earlier
    user message, in the system prompt, or past char 500 of a long prompt — all
    still sent to the LLM but never scanned. assistant messages (the model's own
    prior output) are excluded to avoid injection false-positives on them.
    """
    parts: list = []

    # Anthropic puts the system prompt in a SEPARATE top-level `system` kwarg
    # (not in messages). It can be a plain string or a list of text blocks
    # (system + cache_control). Without this, PII/injection in an Anthropic
    # system prompt was never scanned.
    system = kwargs.get("system")
    if isinstance(system, str):
        if system:
            parts.append(system)
    elif isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and block.get("type") == "text":
                txt = block.get("text", "") or ""
                if txt:
                    parts.append(txt)

    messages = kwargs.get("messages") or []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") not in ("user", "system", "tool"):
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            if content:
                parts.append(content)
        elif isinstance(content, list):
            # OpenAI multimodal content: list of {type, text|...} parts.
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    txt = part.get("text", "") or ""
                    if txt:
                        parts.append(txt)
        if sum(len(p) for p in parts) >= _GATE_SCAN_CAP:
            break  # enough text gathered; stop before scanning megabytes
    if not parts:
        return None
    return "\n".join(parts)[:_GATE_SCAN_CAP]


def _extract_langchain_prompts(prompts) -> "str | None":
    """Concatenate ALL string prompts in a LangChain batch — not just prompts[0],
    which let PII in a later batch entry bypass the gate."""
    if not prompts:
        return None
    parts = [p for p in prompts if isinstance(p, str) and p]
    if not parts:
        return None
    return "\n".join(parts)[:_GATE_SCAN_CAP]


def _provider_from_model(model: str) -> str:
    m = (model or "").lower()
    if "gpt" in m or m.startswith("o1") or m.startswith("o3"):
        return "openai"
    if "claude" in m:
        return "anthropic"
    if "gemini" in m:
        return "google"
    return "other"


def _maybe_gate_check(model: str, prompt: "str | None" = None) -> None:
    """
    Pre-call compliance gate + human-approval check.

    Order:
      1. Local cached policy for the active agent (set via enforce=[...] or
         init(enforce=[...]) or the active tl.using scope) — <1ms, no hop.
      2. Server-side gate check, only when gate_enabled and no local policy.
      3. Human approval (require_approval_when) once the gate has allowed.
    Raises ComplianceViolation on "block". On gate infrastructure error the
    call is allowed through (fail-open); approvals fail closed.
    """
    from trustlayer.tracker import ComplianceViolation

    # Resolve which agent this call belongs to: active run (scope/ambient).
    run = _get_current_run()
    agent_name = (run.agent_name if run is not None else None) or _ambient_config["agent_name"]

    decided = False
    # 1. Local enforcement (policy cached by enforce=[...])
    try:
        from trustlayer.gate_local import get_shared_cache
        cache = get_shared_cache()
        if cache:
            result = cache.check(agent_name, action_type="llm_call", prompt=prompt)
            if result is not None:
                decided = True
                if result.get("decision") == "block":
                    raise ComplianceViolation(
                        reason=result.get("reason", "Compliance gate blocked this LLM call."),
                        rule_id=result.get("rule_id"),
                    )
    except ComplianceViolation:
        raise
    except Exception as _exc:
        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)

    # 2. Server fallback (only if no local policy decided)
    if not decided and _ambient_config.get("gate_enabled"):
        global _server_gate_cooldown_until
        fail_closed = bool(_ambient_config.get("fail_closed"))
        # In fail-open mode, skip the server gate while in cooldown so a down API
        # doesn't add the gate timeout to every call. fail_closed must always try
        # (it blocks when the gate can't be reached, so skipping would be unsafe).
        if not fail_closed and time.time() < _server_gate_cooldown_until:
            pass
        else:
            try:
                result = _get_ambient_client().gate_check(
                    agent_id=agent_name,
                    action_type="llm_call",
                    prompt=prompt,
                )
                if result.get("decision") == "block":
                    raise ComplianceViolation(
                        reason=result.get("reason", "Compliance gate blocked this LLM call."),
                        rule_id=result.get("rule_id"),
                    )
                # Gate unreachable (fail-open sentinel) → start a cooldown so the
                # next calls don't each eat the gate timeout.
                if result.get("rule_id") == "gate_unreachable" or \
                        str(result.get("reason", "")).startswith("Gate unreachable"):
                    _server_gate_cooldown_until = time.time() + _SERVER_GATE_COOLDOWN_SEC
            except ComplianceViolation:
                raise
            except Exception:
                # fail-open: never block a call due to gate infrastructure failure
                _server_gate_cooldown_until = time.time() + _SERVER_GATE_COOLDOWN_SEC

    # 3. Human-in-the-loop approval (after the gate allows).
    _maybe_require_approval(
        model, action_type="llm_call", prompt=prompt,
        provider=_provider_from_model(model),
    )


def _resolve_approval_config():
    """
    Resolve the active human-approval config in priority order:
    active tl.using(...) scope -> process-wide init() ambient default.
    Returns (predicate, approval_dict, agent_name).
    """
    from trustlayer.tracker import _current_scope
    scope = _current_scope()
    if scope and scope.get("require_approval_when") is not None:
        return (
            scope["require_approval_when"],
            scope.get("approval") or {},
            scope.get("agent_name") or _ambient_config["agent_name"],
        )
    run = _get_current_run()
    agent_name = (run.agent_name if run is not None else None) or _ambient_config["agent_name"]
    return (
        _ambient_config.get("require_approval_when"),
        _ambient_config.get("approval") or {},
        agent_name,
    )


def _maybe_require_approval(
    model: str,
    *,
    action_type: str = "llm_call",
    prompt: "str | None" = None,
    tool_name: "str | None" = None,
    tool_args: "dict | None" = None,
    provider: str = "other",
) -> None:
    """
    Human-in-the-loop gate. If a ``require_approval_when`` predicate is
    configured (via tl.init or the active tl.using scope) and it returns True
    for this call's context, pause until a human approves in the FORMA inbox.

    Raises ApprovalRejectedError / ApprovalTimeoutError on a negative outcome.
    A predicate that raises is treated as fail-closed (approval required).
    """
    predicate, approval, agent_name = _resolve_approval_config()
    if predicate is None:
        return

    ctx = {
        "agent_name": agent_name,
        "provider": provider,
        "model": model,
        "action_type": action_type,
        "prompt": prompt,
        "tool_name": tool_name,
        "tool_args": tool_args,
    }
    try:
        needs = bool(predicate(ctx))
    except Exception:
        needs = True  # predicate error -> fail-closed (require human review)
    if not needs:
        return

    from trustlayer.approval import wait_for_forma_approval
    run = _get_current_run()
    run_id = getattr(run, "run_id", None)
    title = approval.get("title") or f"{agent_name}: decision requires approval"
    message = approval.get("message") or "An AI agent is requesting approval to proceed."
    wait_for_forma_approval(
        _get_ambient_client(),
        agent_name=agent_name,
        run_id=run_id,
        title=title,
        message=message,
        payload={"model": model, "action_type": action_type,
                 "prompt_preview": (prompt or "")[:500],
                 "tool_name": tool_name},
        timeout=int(approval.get("timeout") or 3600),
        poll_interval=int(approval.get("poll_interval") or 5),
    )


def _flush_ambient_run(run) -> None:
    """Finalize and synchronously POST a single ambient run to the API."""
    if getattr(run, "_forma_flushed", False) or not run.steps:
        return
    run._forma_flushed = True  # guard against double-flush
    try:
        from trustlayer.models import RunStatus
        from trustlayer.crypto import sign_run as _sign_run

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
        if run.status == RunStatus.RUNNING:
            run.status = RunStatus.SUCCESS

        # Hard per-run cost cap (init(max_cost_usd=...))
        max_cost = _ambient_config.get("max_cost_usd")
        if max_cost is not None and run.total_cost_usd > max_cost:
            run.status = RunStatus.FAILED
            run.error = f"Cost limit exceeded: ${run.total_cost_usd:.4f} > ${max_cost}"

        run_dict = run.to_dict()
        run.signature = _sign_run(run_dict, secret_key=_ambient_config["api_key"])
        _get_ambient_client()._post_run(run)  # synchronous — safe inside atexit
    except Exception as _exc:
        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)


def _flush_all_ambient_runs() -> None:
    """atexit handler: finalize and flush all pending ambient runs."""
    with _ambient_runs_lock:
        runs = list(_ambient_runs)
        _ambient_runs.clear()
    for run in runs:
        _flush_ambient_run(run)


# ── Step injection ────────────────────────────────────────────────────────────

def _add_llm_step(label: str, model: str, prompt_tokens: int,
                  completion_tokens: int, duration_ms: int,
                  finish_reason: Optional[str] = None, error: Optional[str] = None):
    from trustlayer.models import TraceStep, StepType
    run = _get_current_run()
    if run is None:
        cost_usd = _estimate_cost(model, prompt_tokens, completion_tokens)
        provider = ("openai" if "gpt" in model.lower()
                    else "anthropic" if "claude" in model.lower()
                    else "litellm" if "litellm" in label.lower()
                    else "langchain" if "langchain" in label.lower()
                    else "other")
        _record_shadow_event(model, provider, prompt_tokens, completion_tokens, cost_usd)
        return

    step_number = len(run.steps) + 1
    cost_usd = _estimate_cost(model, prompt_tokens, completion_tokens)
    step = TraceStep(
        step_number=step_number,
        step_type=StepType.LLM,
        label=label,
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        duration_ms=duration_ms,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost_usd=cost_usd,
        status="success" if not error else "error",
        error=error,
    )
    if finish_reason:
        step.tool_args = {"finish_reason": finish_reason}
    run.steps.append(step)


# ── OpenAI patcher (v1 SDK — class-level, sync + async) ──────────────────────

def _patch_openai():
    try:
        from openai.resources.chat.completions import Completions
    except ImportError:
        return

    if getattr(Completions, "_trustlayer_patched", False):
        return

    orig_create = Completions.create

    @functools.wraps(orig_create)
    def patched_create(self_client, *args, **kwargs):
        _check_kill()
        _maybe_gate_check(kwargs.get("model", ""), _extract_prompt(kwargs))
        _ensure_ambient_run()
        t0 = time.monotonic()
        error = None
        response = None
        try:
            response = orig_create(self_client, *args, **kwargs)
            return response
        except Exception as exc:
            error = str(exc)
            raise
        finally:
            duration_ms = int((time.monotonic() - t0) * 1000)
            model = kwargs.get("model", "unknown")
            prompt_tokens = completion_tokens = 0
            finish_reason = None
            if response is not None:
                try:
                    if response.usage:
                        prompt_tokens = response.usage.prompt_tokens or 0
                        completion_tokens = response.usage.completion_tokens or 0
                    choices = getattr(response, "choices", [])
                    if choices:
                        finish_reason = getattr(choices[0], "finish_reason", None)
                except Exception as _exc:
                    logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
            _add_llm_step(f"OpenAI {model}", model, prompt_tokens,
                          completion_tokens, duration_ms, finish_reason, error)

    Completions.create = patched_create
    Completions._trustlayer_patched = True  # type: ignore[attr-defined]

    # Async variant
    try:
        from openai.resources.chat.completions import AsyncCompletions
        if not getattr(AsyncCompletions, "_trustlayer_patched", False):
            orig_acreate = AsyncCompletions.create

            @functools.wraps(orig_acreate)
            async def patched_acreate(self_client, *args, **kwargs):
                _check_kill()
                _maybe_gate_check(kwargs.get("model", ""), _extract_prompt(kwargs))
                _ensure_ambient_run()
                t0 = time.monotonic()
                error = None
                response = None
                try:
                    response = await orig_acreate(self_client, *args, **kwargs)
                    return response
                except Exception as exc:
                    error = str(exc)
                    raise
                finally:
                    duration_ms = int((time.monotonic() - t0) * 1000)
                    model = kwargs.get("model", "unknown")
                    prompt_tokens = completion_tokens = 0
                    finish_reason = None
                    if response is not None:
                        try:
                            if response.usage:
                                prompt_tokens = response.usage.prompt_tokens or 0
                                completion_tokens = response.usage.completion_tokens or 0
                            choices = getattr(response, "choices", [])
                            if choices:
                                finish_reason = getattr(choices[0], "finish_reason", None)
                        except Exception as _exc:
                            logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
                    _add_llm_step(f"OpenAI {model}", model, prompt_tokens,
                                  completion_tokens, duration_ms, finish_reason, error)

            AsyncCompletions.create = patched_acreate
            AsyncCompletions._trustlayer_patched = True  # type: ignore[attr-defined]
    except (ImportError, AttributeError) as _exc:
        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)


# ── Anthropic patcher (class-level, sync + async) ────────────────────────────

def _patch_anthropic():
    try:
        from anthropic.resources.messages import Messages
    except ImportError:
        return

    if getattr(Messages, "_trustlayer_patched", False):
        return

    orig_create = Messages.create

    @functools.wraps(orig_create)
    def patched_create(self_client, *args, **kwargs):
        _check_kill()
        _maybe_gate_check(kwargs.get("model", ""), _extract_prompt(kwargs))
        _ensure_ambient_run()
        t0 = time.monotonic()
        error = None
        response = None
        try:
            response = orig_create(self_client, *args, **kwargs)
            return response
        except Exception as exc:
            error = str(exc)
            raise
        finally:
            duration_ms = int((time.monotonic() - t0) * 1000)
            model = kwargs.get("model", "unknown")
            prompt_tokens = completion_tokens = 0
            if response is not None:
                try:
                    usage = getattr(response, "usage", None)
                    if usage:
                        prompt_tokens = getattr(usage, "input_tokens", 0) or 0
                        completion_tokens = getattr(usage, "output_tokens", 0) or 0
                except Exception as _exc:
                    logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
            _add_llm_step(f"Anthropic {model}", model, prompt_tokens,
                          completion_tokens, duration_ms, error=error)

    Messages.create = patched_create
    Messages._trustlayer_patched = True  # type: ignore[attr-defined]

    # Async variant
    try:
        from anthropic.resources.messages import AsyncMessages
        if not getattr(AsyncMessages, "_trustlayer_patched", False):
            orig_acreate = AsyncMessages.create

            @functools.wraps(orig_acreate)
            async def patched_acreate(self_client, *args, **kwargs):
                _check_kill()
                _maybe_gate_check(kwargs.get("model", ""), _extract_prompt(kwargs))
                _ensure_ambient_run()
                t0 = time.monotonic()
                error = None
                response = None
                try:
                    response = await orig_acreate(self_client, *args, **kwargs)
                    return response
                except Exception as exc:
                    error = str(exc)
                    raise
                finally:
                    duration_ms = int((time.monotonic() - t0) * 1000)
                    model = kwargs.get("model", "unknown")
                    prompt_tokens = completion_tokens = 0
                    if response is not None:
                        try:
                            usage = getattr(response, "usage", None)
                            if usage:
                                prompt_tokens = getattr(usage, "input_tokens", 0) or 0
                                completion_tokens = getattr(usage, "output_tokens", 0) or 0
                        except Exception as _exc:
                            logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
                    _add_llm_step(f"Anthropic {model}", model, prompt_tokens,
                                  completion_tokens, duration_ms, error=error)

            AsyncMessages.create = patched_acreate
            AsyncMessages._trustlayer_patched = True  # type: ignore[attr-defined]
    except (ImportError, AttributeError) as _exc:
        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)


# ── LiteLLM patcher (module-level function, sync + async) ────────────────────

def _patch_litellm():
    try:
        import litellm
    except ImportError:
        return

    if getattr(litellm, "_trustlayer_patched", False):
        return

    # Sync: litellm.completion(...)
    orig_completion = litellm.completion

    @functools.wraps(orig_completion)
    def patched_completion(*args, **kwargs):
        _check_kill()
        _maybe_gate_check(
            str(kwargs.get("model") or (args[0] if args else "unknown")),
            _extract_prompt(kwargs),
        )
        _ensure_ambient_run()
        t0 = time.monotonic()
        error = None
        response = None
        try:
            response = orig_completion(*args, **kwargs)
            return response
        except Exception as exc:
            error = str(exc)
            raise
        finally:
            duration_ms = int((time.monotonic() - t0) * 1000)
            model = kwargs.get("model") or (args[0] if args else "unknown")
            prompt_tokens = completion_tokens = 0
            finish_reason = None
            if response is not None:
                try:
                    usage = getattr(response, "usage", None)
                    if usage:
                        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
                        completion_tokens = getattr(usage, "completion_tokens", 0) or 0
                    choices = getattr(response, "choices", [])
                    if choices:
                        finish_reason = getattr(choices[0], "finish_reason", None)
                except Exception as _exc:
                    logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
            _add_llm_step(f"LiteLLM {model}", str(model), prompt_tokens,
                          completion_tokens, duration_ms, finish_reason, error)

    litellm.completion = patched_completion

    # Async: litellm.acompletion(...)
    try:
        orig_acompletion = litellm.acompletion

        @functools.wraps(orig_acompletion)
        async def patched_acompletion(*args, **kwargs):
            _check_kill()
            _maybe_gate_check(
                str(kwargs.get("model") or (args[0] if args else "unknown")),
                _extract_prompt(kwargs),
            )
            _ensure_ambient_run()
            t0 = time.monotonic()
            error = None
            response = None
            try:
                response = await orig_acompletion(*args, **kwargs)
                return response
            except Exception as exc:
                error = str(exc)
                raise
            finally:
                duration_ms = int((time.monotonic() - t0) * 1000)
                model = kwargs.get("model") or (args[0] if args else "unknown")
                prompt_tokens = completion_tokens = 0
                finish_reason = None
                if response is not None:
                    try:
                        usage = getattr(response, "usage", None)
                        if usage:
                            prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
                            completion_tokens = getattr(usage, "completion_tokens", 0) or 0
                        choices = getattr(response, "choices", [])
                        if choices:
                            finish_reason = getattr(choices[0], "finish_reason", None)
                    except Exception as _exc:
                        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
                _add_llm_step(f"LiteLLM {model}", str(model), prompt_tokens,
                              completion_tokens, duration_ms, finish_reason, error)

        litellm.acompletion = patched_acompletion
    except AttributeError as _exc:
        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)

    litellm._trustlayer_patched = True  # type: ignore[attr-defined]


# ── LangChain patcher (class-level _generate / _agenerate hook) ──────────────

def _patch_langchain():
    BaseLLM = None
    # Try langchain-core first (modern), then legacy langchain
    for module_path in (
        "langchain_core.language_models.llms",
        "langchain.llms.base",
    ):
        try:
            mod = __import__(module_path, fromlist=["BaseLLM"])
            BaseLLM = getattr(mod, "BaseLLM", None)
            if BaseLLM is not None:
                break
        except ImportError:
            continue

    if BaseLLM is None:
        return

    if getattr(BaseLLM, "_trustlayer_patched", False):
        return

    # Sync: _generate(prompts, stop, run_manager, **kwargs) → LLMResult
    orig_generate = BaseLLM._generate  # type: ignore[attr-defined]

    @functools.wraps(orig_generate)
    def patched_generate(self, prompts, *args, **kwargs):
        _check_kill()
        _maybe_gate_check(
            str(getattr(self, "model_name", None) or getattr(self, "model", None) or "langchain"),
            _extract_langchain_prompts(prompts),
        )
        _ensure_ambient_run()
        t0 = time.monotonic()
        error = None
        result = None
        try:
            result = orig_generate(self, prompts, *args, **kwargs)
            return result
        except Exception as exc:
            error = str(exc)
            raise
        finally:
            duration_ms = int((time.monotonic() - t0) * 1000)
            model_name = (getattr(self, "model_name", None)
                          or getattr(self, "model", None)
                          or type(self).__name__)
            prompt_tokens = completion_tokens = 0
            if result is not None:
                try:
                    llm_out = getattr(result, "llm_output", None) or {}
                    usage = llm_out.get("token_usage", {}) or {}
                    prompt_tokens = usage.get("prompt_tokens", 0)
                    completion_tokens = usage.get("completion_tokens", 0)
                except Exception as _exc:
                    logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
            _add_llm_step(f"LangChain {model_name}", str(model_name),
                          prompt_tokens, completion_tokens, duration_ms, error=error)

    BaseLLM._generate = patched_generate  # type: ignore[attr-defined]

    # Async: _agenerate
    try:
        orig_agenerate = BaseLLM._agenerate  # type: ignore[attr-defined]

        @functools.wraps(orig_agenerate)
        async def patched_agenerate(self, prompts, *args, **kwargs):
            _check_kill()
            _maybe_gate_check(
                str(getattr(self, "model_name", None) or getattr(self, "model", None) or "langchain"),
                _extract_langchain_prompts(prompts),
            )
            _ensure_ambient_run()
            t0 = time.monotonic()
            error = None
            result = None
            try:
                result = await orig_agenerate(self, prompts, *args, **kwargs)
                return result
            except Exception as exc:
                error = str(exc)
                raise
            finally:
                duration_ms = int((time.monotonic() - t0) * 1000)
                model_name = (getattr(self, "model_name", None)
                              or getattr(self, "model", None)
                              or type(self).__name__)
                prompt_tokens = completion_tokens = 0
                if result is not None:
                    try:
                        llm_out = getattr(result, "llm_output", None) or {}
                        usage = llm_out.get("token_usage", {}) or {}
                        prompt_tokens = usage.get("prompt_tokens", 0)
                        completion_tokens = usage.get("completion_tokens", 0)
                    except Exception as _exc:
                        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
                _add_llm_step(f"LangChain {model_name}", str(model_name),
                              prompt_tokens, completion_tokens, duration_ms, error=error)

        BaseLLM._agenerate = patched_agenerate  # type: ignore[attr-defined]
    except AttributeError as _exc:
        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)

    BaseLLM._trustlayer_patched = True  # type: ignore[attr-defined]


# ── Public API ────────────────────────────────────────────────────────────────

def patch_all():
    """
    Patch all supported LLM clients. Idempotent — safe to call multiple times.
    Called automatically when auto_capture=True on FormaTracker.

    Patched providers:
      - OpenAI  (sync + async, openai>=1.0)
      - Anthropic (sync + async, anthropic>=0.20)
      - LiteLLM (sync + async)
      - LangChain / LangChain-Core (BaseLLM._generate + _agenerate)
    """
    global _patched, _shadow_flush_started
    if _patched:
        return
    _patched = True
    _patch_openai()
    _patch_anthropic()
    _patch_litellm()
    _patch_langchain()
    if not _shadow_flush_started:
        _shadow_flush_started = True
        _flush_shadow_events()


def unpatch_all():
    """Reset the patched flag (for testing). Does not undo monkey-patches."""
    global _patched
    _patched = False
