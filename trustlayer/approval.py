"""
Human-in-the-Loop Approval

Pauses execution until an explicit human decision is recorded in the FORMA
Approvals inbox. This is configured declaratively via tl.init(
require_approval_when=...) / tl.using(require_approval_when=...) — there is NO
decorator. The auto-capture layer evaluates the predicate before each captured
LLM call and, when it returns True, calls wait_for_forma_approval() below.

Flow:
  1. A predicate ``ctx -> bool`` decides whether this call needs human review.
  2. If yes, an approval request is created in the FORMA inbox (/approvals).
  3. Execution blocks (polling /api/approvals/{id}) until:
     - approved  → execution continues
     - rejected  → ApprovalRejectedError is raised
     - expired / timeout → ApprovalTimeoutError is raised
  4. Both the request and the decision are signed audit events — the EU AI Act
     Article 14 / RBI human-review workflow.
"""
from __future__ import annotations

import time
from typing import Any, Optional


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


def wait_for_forma_approval(
    client: Any,
    *,
    agent_name: str,
    run_id: Optional[str] = None,
    title: str = "AI decision requires approval",
    message: Optional[str] = None,
    payload: Optional[dict] = None,
    timeout: int = 3600,
    poll_interval: int = 5,
) -> None:
    """
    Create an approval request in the FORMA inbox and block until a human
    decides. Returns on approval; raises on rejection/timeout.

    Fail-closed: if the API is unreachable (no request id) we raise
    ApprovalTimeoutError so a skipped human review never silently passes.
    """
    req = client.create_approval(
        agent_name=agent_name,
        run_id=run_id,
        title=title,
        message=message or "An AI agent is requesting approval to proceed.",
        payload=payload or {},
        timeout_seconds=timeout,
    )
    if not req or not req.get("id"):
        raise ApprovalTimeoutError(run_id=run_id or "unknown", timeout=0)

    approval_id = req["id"]
    print(f"[FORMA] \u23f8  Approval {approval_id} pending in the FORMA inbox. "
          f"Waiting up to {timeout}s...")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        data = client.get_approval(approval_id) or {}
        status = data.get("status", "pending")
        if status == "approved":
            print(f"[FORMA] \u2713 Approval {approval_id} approved by "
                  f"{data.get('decided_by', 'reviewer')}.")
            return
        if status == "rejected":
            raise ApprovalRejectedError(
                run_id=approval_id, reason=data.get("decision_reason") or "",
            )
        if status == "expired":
            raise ApprovalTimeoutError(run_id=approval_id, timeout=timeout)

    raise ApprovalTimeoutError(run_id=approval_id, timeout=timeout)
