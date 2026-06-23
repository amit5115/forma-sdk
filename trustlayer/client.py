"""
HTTP client for the FORMA API.

All requests go through one transport (`_http`) that:
  • retries transient failures (timeouts, connection errors, 429, 5xx) with
    exponential backoff + jitter, respecting the server's Retry-After;
  • attaches an Idempotency-Key on mutating requests so a retry never
    double-creates (pairs with the server's idempotency middleware);
  • raises a typed error (FormaAuthError / FormaRateLimitError / FormaAPIError /
    FormaConnectionError) parsed from the standardized `{error:{code,message}}`.

Best-effort callers (run reporting, gate decision logs) catch and degrade; the
synchronous gate check fails open by default (configurable via fail_closed).
"""
import json
import logging
import random
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import TYPE_CHECKING, Any, Dict, Optional

from .errors import (
    FormaAPIError,
    FormaAuthError,
    FormaConnectionError,
    FormaRateLimitError,
)

if TYPE_CHECKING:
    from .models import AgentRun

logger = logging.getLogger("trustlayer")

_UA = "FORMA-SDK/2.3.16"
_RETRYABLE_STATUS = lambda s: s == 429 or 500 <= s < 600  # noqa: E731


def _parse_error(http_err: urllib.error.HTTPError) -> Dict[str, Any]:
    try:
        body = json.loads(http_err.read().decode("utf-8", "replace"))
        err = body.get("error", {})
        return {"code": err.get("code"), "message": err.get("message") or http_err.reason}
    except Exception:
        return {"code": None, "message": getattr(http_err, "reason", "API error")}


def _retry_after(http_err: urllib.error.HTTPError) -> Optional[int]:
    try:
        ra = http_err.headers.get("Retry-After")
        return int(ra) if ra else None
    except Exception:
        return None


class FormaClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://provn-6f5i.onrender.com",
        *,
        timeout: int = 10,
        max_retries: int = 2,
        fail_closed: bool = False,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.fail_closed = fail_closed

    # ── Core transport ─────────────────────────────────────────────────────────
    def _http(
        self,
        method: str,
        path: str,
        *,
        body: Optional[dict] = None,
        timeout: Optional[int] = None,
        idempotent: bool = False,
        retries: Optional[int] = None,
    ) -> Dict[str, Any]:
        timeout = timeout or self.timeout
        # Per-call retry budget. Defaults to self.max_retries; callers on a latency-
        # sensitive hot path (the synchronous gate check) pass retries=0 so a
        # slow/down API fails open fast instead of multiplying LLM latency.
        max_retries = self.max_retries if retries is None else max(0, int(retries))
        url = f"{self.base_url}{path}"
        data = json.dumps(body, default=str).encode("utf-8") if body is not None else None
        headers = {"X-API-Key": self.api_key, "User-Agent": _UA}
        if data is not None:
            headers["Content-Type"] = "application/json"
        # one idempotency key for the whole call — reused across retries so a
        # retried POST is recognised by the server as the same request.
        if idempotent and method in ("POST", "PUT", "PATCH"):
            headers["Idempotency-Key"] = uuid.uuid4().hex

        attempt = 0
        while True:
            try:
                req = urllib.request.Request(url, data=data, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                status = exc.code
                err = _parse_error(exc)
                if status in (401, 403):
                    raise FormaAuthError(err["message"], code=err["code"], status=status)
                if _RETRYABLE_STATUS(status) and attempt < max_retries:
                    self._backoff(attempt, _retry_after(exc))
                    attempt += 1
                    continue
                if status == 429:
                    raise FormaRateLimitError(err["message"], retry_after=_retry_after(exc) or 60,
                                              code=err["code"], status=status)
                raise FormaAPIError(err["message"], code=err["code"], status=status)
            except (urllib.error.URLError, TimeoutError, ConnectionError, socket.timeout) as exc:
                if attempt < max_retries:
                    self._backoff(attempt, None)
                    attempt += 1
                    continue
                raise FormaConnectionError(str(exc))

    @staticmethod
    def _backoff(attempt: int, retry_after: Optional[int]) -> None:
        base = float(retry_after) if retry_after else 0.25 * (2 ** attempt)
        time.sleep(min(base + random.uniform(0, base * 0.5), 10.0))

    # ── Runs (best-effort, background) ─────────────────────────────────────────
    def send_run(self, run: "AgentRun") -> None:
        threading.Thread(target=self._post_run, args=(run,), daemon=True).start()

    def _post_run(self, run: "AgentRun") -> None:
        try:
            self._http("POST", "/api/runs", body=run.to_dict(), idempotent=True)
        except Exception as exc:
            # Connection errors are expected offline/in tests — debug level only
            msg = str(exc)
            if any(x in msg for x in ("Connection refused", "Connection reset", "Name or service not known")):
                logger.debug("Failed to send run to FORMA (offline): %s", exc)
            else:
                logger.warning("Failed to send run to FORMA: %s", exc)

    # ── Gate (synchronous; fail-open by default, configurable) ─────────────────
    def gate_check(
        self,
        agent_id: str,
        action_type: str,
        *,
        prompt: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            # Hot path: a single fast attempt, no retries. The gate check is a
            # real-time pre-flight — if the API is slow/down, fail open (or closed)
            # immediately rather than retrying and stacking seconds onto every call.
            return self._http("POST", "/api/gate/check", timeout=min(self.timeout, 5),
                              retries=0, body={
                "agent_id": agent_id, "action_type": action_type,
                "prompt": prompt, "tool_name": tool_name, "tool_args": tool_args,
            })
        except Exception as exc:
            if self.fail_closed:
                logger.warning("Gate unreachable — failing CLOSED (blocking): %s", exc)
                return {"decision": "block", "rule_id": "gate_unreachable",
                        "reason": "Compliance gate unreachable and fail_closed=True — blocked."}
            logger.debug("Gate check failed (allowing by default): %s", exc)
            return {"decision": "allow", "reason": "Gate unreachable — defaulting to allow.", "rule_id": None}

    # ── Generic request (used by enforcement + approvals helpers) ──────────────
    def _request(self, method: str, path: str, body: Optional[dict] = None, timeout: int = 10):
        return self._http(method, path, body=body, timeout=timeout,
                          idempotent=(method in ("POST", "PUT", "PATCH")))

    def get_policy(self, agent_ref: str) -> Optional[Dict[str, Any]]:
        """Fetch the compiled enforcement policy bundle for an agent."""
        try:
            return self._request("GET", f"/api/gate/policy/{urllib.request.quote(agent_ref)}")
        except Exception as exc:
            logger.debug("Policy fetch failed for %s: %s", agent_ref, exc)
            return None

    def apply_policy(self, agent_ref: str, packs: list) -> Optional[Dict[str, Any]]:
        """Install framework policy packs (e.g. ["dpdp", "rbi_ml_risk"]) on an agent."""
        try:
            return self._request("POST", f"/api/gate/policy/{urllib.request.quote(agent_ref)}/apply",
                                  {"packs": packs})
        except Exception as exc:
            logger.debug("Policy apply failed for %s: %s", agent_ref, exc)
            return None

    def log_gate_decisions(self, entries: list) -> None:
        """Batch-report locally evaluated gate decisions to the audit trail."""
        try:
            self._request("POST", "/api/gate/log", {"entries": entries})
        except Exception as exc:
            logger.debug("Gate decision report failed: %s", exc)

    # ── Approvals (human-in-the-loop) ──────────────────────────────────────────
    def create_approval(
        self,
        agent_name: str,
        *,
        run_id: Optional[str] = None,
        title: str = "AI decision requires approval",
        message: Optional[str] = None,
        payload: Optional[dict] = None,
        timeout_seconds: int = 3600,
    ) -> Optional[Dict[str, Any]]:
        try:
            return self._request("POST", "/api/approvals", {
                "agent_name": agent_name, "run_id": run_id, "title": title,
                "message": message, "payload": payload, "timeout_seconds": timeout_seconds,
            })
        except Exception as exc:
            logger.warning("Approval request creation failed: %s", exc)
            return None

    def get_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        try:
            return self._request("GET", f"/api/approvals/{approval_id}")
        except Exception as exc:
            logger.debug("Approval poll failed: %s", exc)
            return None
