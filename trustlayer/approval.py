"""
Human-in-the-Loop Approval

Provides @require_approval decorator that pauses an agent function and
waits for an explicit human decision before the result is returned.

How it works:
  1. Agent function runs and produces a result.
  2. Before returning, the run is submitted to PROVN with status=pending_approval.
  3. A webhook is sent to the configured URL with the run data + signed token.
  4. Execution blocks (polling /api/runs/{run_id}/approval-status) until:
     - The run is approved → result is returned normally
     - The run is rejected → ApprovalRejectedError is raised
     - Timeout is exceeded → ApprovalTimeoutError is raised
  5. The approval decision (approver identity + timestamp) is appended to the run signature.

Usage:
    tracker = PROVNTracker(...)

    @tracker.track
    @tracker.require_approval(
        via="webhook",
        url="https://hooks.company.com/ai-review",
        timeout=3600,
    )
    def approve_loan(application: dict) -> dict:
        # agent analysis happens here
        return {"decision": "reject", "reason": "DTI ratio too high"}
"""
from __future__ import annotations

import functools
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Optional


class ApprovalRejectedError(Exception):
    """Raised when a human reviewer rejects the agent's output."""
    def __init__(self, run_id: str, reason: str = ""):
        self.run_id = run_id
        self.reason = reason
        super().__init__(f"Run {run_id} was rejected by human reviewer. Reason: {reason}")


class ApprovalTimeoutError(Exception):
    """Raised when the approval timeout is exceeded."""
    def __init__(self, run_id: str, timeout: int):
        self.run_id = run_id
        super().__init__(f"Run {run_id} approval timed out after {timeout}s")


def _send_webhook(url: str, payload: dict, timeout: int = 10):
    """Send a JSON webhook. Best-effort — failures are logged but not raised."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "PROVN-SDK/0.3"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout):
            pass
    except Exception as exc:
        print(f"[PROVN] Approval webhook failed: {exc}")


def _poll_approval_status(api_url: str, api_key: str, run_id: str, poll_interval: int, timeout: int) -> str:
    """
    Poll /api/runs/{run_id}/approval-status until approved/rejected or timeout.
    Returns: "approved" | "rejected" | "timeout"
    """
    deadline = time.monotonic() + timeout
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(
                f"{api_url}/api/runs/{run_id}/approval-status",
                headers=headers,
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                status = data.get("approval_status", "pending")
                if status in ("approved", "rejected"):
                    return status
        except Exception:
            pass
        time.sleep(poll_interval)

    return "timeout"


class RequireApprovalDecorator:
    """
    Returned by tracker.require_approval(...). Wraps a function to pause
    and wait for human approval before returning the result.

    via="forma" (default): creates an approval request in the FORMA
    Approvals inbox (/approvals in the dashboard) and polls until a human
    approves/rejects. Both the request and the decision are signed audit
    events — this is the EU AI Act Article 14 / RBI human-review workflow.

    via="webhook": legacy flow — sends a webhook to `url` and polls the
    run-level approval status endpoint.

    `when` (optional): callable(result) -> bool. Approval is only required
    when it returns True — e.g. when=lambda r: r["amount"] > 1_000_000.
    """

    def __init__(
        self,
        tracker: Any,
        via: str = "forma",
        url: Optional[str] = None,
        timeout: int = 3600,
        poll_interval: int = 5,
        message: Optional[str] = None,
        when: Optional[Callable[[Any], bool]] = None,
        title: Optional[str] = None,
    ):
        self.tracker = tracker
        self.via = via
        self.url = url or os.environ.get("TRUSTLAYER_APPROVAL_WEBHOOK_URL", "")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.message = message or "An AI agent is requesting approval to proceed."
        self.when = when
        self.title = title

    def __call__(self, func: Callable) -> Callable:
        decorator = self

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            from trustlayer.tracker import _current_run

            # Run the agent function
            result = func(*args, **kwargs)

            # Conditional approval: skip when the predicate says it's low-stakes
            if decorator.when is not None:
                try:
                    if not decorator.when(result):
                        return result
                except Exception:
                    pass  # predicate error → default to requiring approval

            # Get the current run (set by @track wrapper above this in call stack)
            run = _current_run()
            run_id = run.run_id if run else None
            agent_name = (run.agent_name if run else None) or getattr(decorator.tracker, "agent_name", None) or func.__name__

            if decorator.via == "forma":
                return decorator._forma_flow(agent_name, run_id, result)

            # ── Legacy webhook flow ────────────────────────────────────────
            if decorator.via == "webhook" and decorator.url:
                payload = {
                    "event": "approval_required",
                    "run_id": run_id,
                    "agent_name": agent_name,
                    "human_sponsor": run.human_sponsor if run else "unknown",
                    "message": decorator.message,
                    "result_preview": str(result)[:500],
                    "approve_url": f"{decorator.tracker.api_url}/api/runs/{run_id}/approve",
                    "reject_url": f"{decorator.tracker.api_url}/api/runs/{run_id}/reject",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                _send_webhook(decorator.url, payload)

            print(f"[FORMA] ⏸  Run {run_id} is pending human approval. Waiting up to {decorator.timeout}s...")

            decision = _poll_approval_status(
                api_url=decorator.tracker.api_url,
                api_key=decorator.tracker.api_key,
                run_id=run_id or "unknown",
                poll_interval=decorator.poll_interval,
                timeout=decorator.timeout,
            )

            if decision == "approved":
                print(f"[FORMA] ✓ Run {run_id} approved by human reviewer.")
                return result
            elif decision == "rejected":
                raise ApprovalRejectedError(run_id=run_id or "unknown")
            else:
                raise ApprovalTimeoutError(run_id=run_id or "unknown", timeout=decorator.timeout)

        return wrapper

    def _forma_flow(self, agent_name: str, run_id: Optional[str], result: Any):
        """Create an approval in the FORMA inbox and block until decided."""
        client = self.tracker._client
        req = client.create_approval(
            agent_name=agent_name,
            run_id=run_id,
            title=self.title or f"{agent_name}: decision requires approval",
            message=self.message,
            payload={"result_preview": str(result)[:1000]},
            timeout_seconds=self.timeout,
        )
        if not req or not req.get("id"):
            # API unreachable — fail-closed for approvals (a skipped human
            # review must not silently pass)
            raise ApprovalTimeoutError(run_id=run_id or "unknown", timeout=0)

        approval_id = req["id"]
        print(f"[FORMA] ⏸  Approval {approval_id} pending in the FORMA inbox. Waiting up to {self.timeout}s...")

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            time.sleep(self.poll_interval)
            data = client.get_approval(approval_id) or {}
            status = data.get("status", "pending")
            if status == "approved":
                print(f"[FORMA] ✓ Approval {approval_id} approved by {data.get('decided_by', 'reviewer')}.")
                return result
            if status == "rejected":
                raise ApprovalRejectedError(
                    run_id=approval_id, reason=data.get("decision_reason") or "",
                )
            if status == "expired":
                raise ApprovalTimeoutError(run_id=approval_id, timeout=self.timeout)

        raise ApprovalTimeoutError(run_id=approval_id, timeout=self.timeout)
