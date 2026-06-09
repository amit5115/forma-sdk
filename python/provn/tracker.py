"""Run tracker — @provn.track decorator and step recorder."""
import functools
import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, TypeVar

F = TypeVar("F", bound=Callable)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sign_run(run_id: str, api_key: str) -> str:
    payload = f"{run_id}:{api_key}"
    return "hmac-sha256:" + hashlib.sha256(payload.encode()).hexdigest()[:32]


class RunContext:
    """Tracks steps within a run, accumulating tokens/cost."""

    def __init__(self, run_id: str, agent_name: str):
        self.run_id = run_id
        self.agent_name = agent_name
        self.steps: List[Dict[str, Any]] = []
        self._step_counter = 0
        self.total_tokens = 0
        self.total_cost_usd = 0.0

    def add_llm_step(
        self,
        label: str,
        model: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost_usd: float = 0.0,
        duration_ms: Optional[int] = None,
    ) -> None:
        self._step_counter += 1
        self.total_tokens += prompt_tokens + completion_tokens
        self.total_cost_usd += cost_usd
        self.steps.append({
            "step_number":        self._step_counter,
            "step_type":          "llm",
            "label":              label,
            "model":              model,
            "prompt_tokens":      prompt_tokens,
            "completion_tokens":  completion_tokens,
            "cost_usd":           cost_usd,
            "duration_ms":        duration_ms,
            "status":             "success",
        })

    def add_tool_step(
        self,
        tool_name: str,
        tool_args: Optional[Dict] = None,
        tool_result: Optional[str] = None,
        duration_ms: Optional[int] = None,
        error: Optional[str] = None,
    ) -> None:
        self._step_counter += 1
        self.steps.append({
            "step_number": self._step_counter,
            "step_type":   "tool",
            "label":       f"Tool: {tool_name}",
            "tool_name":   tool_name,
            "tool_args":   tool_args,
            "tool_result": tool_result,
            "duration_ms": duration_ms,
            "error":       error,
            "status":      "error" if error else "success",
        })


# Thread-local context (set by @track during execution)
import threading
_ctx_local = threading.local()


def current_run() -> Optional[RunContext]:
    """Get the current RunContext from inside a @track-decorated function."""
    return getattr(_ctx_local, "run_ctx", None)


def track(func: Optional[F] = None, *, name: Optional[str] = None, version: str = "1.0.0") -> Any:
    """
    Decorator that wraps an agent function with PROVN tracking.

    Usage:
        @provn.track
        def my_agent(task: str) -> str:
            ...

        @provn.track(name="summarizer", version="2.0.0")
        def summarize(text: str) -> str:
            ...
    """
    if func is None:
        return lambda f: track(f, name=name, version=version)

    agent_name = name or func.__name__

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        from provn import _client
        if _client is None:
            return func(*args, **kwargs)

        run_id = f"run_{uuid.uuid4().hex[:12]}"
        ctx = RunContext(run_id=run_id, agent_name=agent_name)
        _ctx_local.run_ctx = ctx

        started_at = _now_iso()
        t0 = time.monotonic()
        status = "success"
        error_msg: Optional[str] = None

        try:
            result = func(*args, **kwargs)
            return result
        except Exception as exc:
            status = "failed"
            error_msg = str(exc)
            raise
        finally:
            duration_ms = int((time.monotonic() - t0) * 1000)
            ended_at = _now_iso()
            sig = _sign_run(run_id, _client.api_key)
            try:
                _client.submit_run(
                    run_id=run_id,
                    agent_name=agent_name,
                    agent_version=version,
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=duration_ms,
                    status=status,
                    steps=ctx.steps,
                    total_tokens=ctx.total_tokens,
                    total_cost_usd=ctx.total_cost_usd,
                    error=error_msg,
                    signature=sig,
                )
            except Exception:
                pass  # Never fail the agent due to observability
            _ctx_local.run_ctx = None

    return wrapper


# Async variant
def track_async(func: Optional[F] = None, *, name: Optional[str] = None, version: str = "1.0.0") -> Any:
    """
    Async decorator: @provn.track_async or @provn.track_async(name="x")
    """
    if func is None:
        return lambda f: track_async(f, name=name, version=version)

    import asyncio
    import concurrent.futures
    agent_name = name or func.__name__

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        from provn import _client
        if _client is None:
            return await func(*args, **kwargs)

        run_id = f"run_{uuid.uuid4().hex[:12]}"
        ctx = RunContext(run_id=run_id, agent_name=agent_name)
        _ctx_local.run_ctx = ctx

        started_at = _now_iso()
        t0 = time.monotonic()
        status = "success"
        error_msg: Optional[str] = None

        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as exc:
            status = "failed"
            error_msg = str(exc)
            raise
        finally:
            duration_ms = int((time.monotonic() - t0) * 1000)
            ended_at = _now_iso()
            sig = _sign_run(run_id, _client.api_key)
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: _client.submit_run(
                        run_id=run_id,
                        agent_name=agent_name,
                        agent_version=version,
                        started_at=started_at,
                        ended_at=ended_at,
                        duration_ms=duration_ms,
                        status=status,
                        steps=ctx.steps,
                        total_tokens=ctx.total_tokens,
                        total_cost_usd=ctx.total_cost_usd,
                        error=error_msg,
                        signature=sig,
                    ),
                )
            except Exception:
                pass
            _ctx_local.run_ctx = None

    return wrapper
