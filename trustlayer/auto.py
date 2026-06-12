"""
Zero-Config Auto-Capture (v2)

Monkey-patches OpenAI, Anthropic, LiteLLM, and LangChain clients so that
every LLM call is automatically captured into the active PROVN run —
without the developer writing any tracking code.

Improvements over v1:
  - Robust class-level patching for OpenAI v1+ SDK (sync + async)
  - Async patching for Anthropic
  - LiteLLM sync + async patching
  - LangChain BaseLLM._generate / _agenerate hook (auto-detects langchain-core)
  - Shadow agent detection for all four providers
"""
from __future__ import annotations

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

# ── Ambient run config (populated by PROVNTracker._configure_ambient) ─────────

_ambient_config: dict = {
    "enabled": False,           # True once provn.init() / trustlayer.init() runs
    "agent_name": "ambient",    # display name for auto-captured runs
    "agent_version": "1.0.0",
    "human_sponsor": "unknown",
    "compliance": [],           # e.g. ["EU_AI_ACT", "RBI_MRM"]
    "gate_enabled": False,      # pre-call compliance gate check
    "kill_event": None,         # threading.Event set by global kill poller
    "api_key": "dev",
    "api_url": "https://forma.2bd.net",
}

_ambient_runs: list = []                                   # all pending ambient runs
_ambient_runs_lock = __import__("threading").Lock()
_atexit_registered = False
_ambient_client = None                                     # cached PROVNClient


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
                api_url = (os.environ.get("FORMA_API_URL") or os.environ.get("TRUSTLAYER_API_URL") or "https://forma.2bd.net").rstrip("/")
                api_key = os.environ.get("FORMA_API_KEY") or os.environ.get("TRUSTLAYER_API_KEY", "dev")
                payload = json.dumps({"events": events}).encode()
                req = urllib.request.Request(
                    url=f"{api_url}/api/shadow/events", data=payload,
                    headers={"X-API-Key": api_key, "Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)
            except Exception:
                pass

    threading.Thread(target=_loop, daemon=True).start()


# ── Ambient run helpers ───────────────────────────────────────────────────────

def _get_ambient_client():
    """Return a cached PROVNClient using the current ambient config."""
    global _ambient_client
    if _ambient_client is None:
        from trustlayer.client import PROVNClient
        _ambient_client = PROVNClient(
            api_key=_ambient_config["api_key"],
            base_url=_ambient_config["api_url"],
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
    """Raise KillSwitchTriggered immediately if the global kill event is set."""
    kill_event = _ambient_config.get("kill_event")
    if kill_event is not None and kill_event.is_set():
        from trustlayer.tracker import KillSwitchTriggered
        raise KillSwitchTriggered(
            f"Kill switch triggered for agent '{_ambient_config['agent_name']}'"
        )


def _extract_prompt(kwargs: dict) -> "str | None":
    """Pull the last user message text from OpenAI-style messages for gate checking."""
    messages = kwargs.get("messages") or []
    for msg in reversed(messages):
        if not isinstance(msg, dict):
            continue
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content[:500]
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        return part.get("text", "")[:500]
    return None


def _maybe_gate_check(model: str, prompt: "str | None" = None) -> None:
    """
    Pre-call compliance gate check. Raises ComplianceViolation on "block".

    Order:
      1. Local cached policy for the active agent (set via enforce=[...] or
         init(enforce=[...])) — <1ms, no network hop.
      2. Server-side gate check, only when gate_enabled and no local policy.
    On any infrastructure error the call is allowed through (fail-open).
    """
    from trustlayer.tracker import ComplianceViolation

    # Resolve which agent this call belongs to: decorated run > ambient agent
    run = _get_current_run()
    agent_name = (run.agent_name if run is not None else None) or _ambient_config["agent_name"]

    # 1. Local enforcement (policy cached by enforce=[...])
    try:
        from trustlayer.gate_local import get_shared_cache
        cache = get_shared_cache()
        if cache:
            result = cache.check(agent_name, action_type="llm_call", prompt=prompt)
            if result is not None:
                if result.get("decision") == "block":
                    raise ComplianceViolation(
                        reason=result.get("reason", "Compliance gate blocked this LLM call."),
                        rule_id=result.get("rule_id"),
                    )
                return
    except ComplianceViolation:
        raise
    except Exception:
        pass

    # 2. Server fallback
    if not _ambient_config.get("gate_enabled"):
        return
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
    except ComplianceViolation:
        raise
    except Exception:
        pass  # fail-open: never block a call due to gate infrastructure failure


def _flush_ambient_run(run) -> None:
    """Finalize and synchronously POST a single ambient run to the API."""
    if getattr(run, "_provn_flushed", False) or not run.steps:
        return
    run._provn_flushed = True  # guard against double-flush
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

        run_dict = run.to_dict()
        run.signature = _sign_run(run_dict, secret_key=_ambient_config["api_key"])
        _get_ambient_client()._post_run(run)  # synchronous — safe inside atexit
    except Exception:
        pass


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
                except Exception:
                    pass
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
                        except Exception:
                            pass
                    _add_llm_step(f"OpenAI {model}", model, prompt_tokens,
                                  completion_tokens, duration_ms, finish_reason, error)

            AsyncCompletions.create = patched_acreate
            AsyncCompletions._trustlayer_patched = True  # type: ignore[attr-defined]
    except (ImportError, AttributeError):
        pass


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
                except Exception:
                    pass
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
                        except Exception:
                            pass
                    _add_llm_step(f"Anthropic {model}", model, prompt_tokens,
                                  completion_tokens, duration_ms, error=error)

            AsyncMessages.create = patched_acreate
            AsyncMessages._trustlayer_patched = True  # type: ignore[attr-defined]
    except (ImportError, AttributeError):
        pass


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
                except Exception:
                    pass
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
                    except Exception:
                        pass
                _add_llm_step(f"LiteLLM {model}", str(model), prompt_tokens,
                              completion_tokens, duration_ms, finish_reason, error)

        litellm.acompletion = patched_acompletion
    except AttributeError:
        pass

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
            prompts[0] if prompts and isinstance(prompts[0], str) else None,
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
                except Exception:
                    pass
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
                prompts[0] if prompts and isinstance(prompts[0], str) else None,
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
                    except Exception:
                        pass
                _add_llm_step(f"LangChain {model_name}", str(model_name),
                              prompt_tokens, completion_tokens, duration_ms, error=error)

        BaseLLM._agenerate = patched_agenerate  # type: ignore[attr-defined]
    except AttributeError:
        pass

    BaseLLM._trustlayer_patched = True  # type: ignore[attr-defined]


# ── Public API ────────────────────────────────────────────────────────────────

def patch_all():
    """
    Patch all supported LLM clients. Idempotent — safe to call multiple times.
    Called automatically when auto_capture=True on PROVNTracker.

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
