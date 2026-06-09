"""
HTTP client for sending run data to the PROVN API.
Sends asynchronously in a background thread so it never blocks the agent.
"""
import json
import logging
import threading
import urllib.request
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from .models import AgentRun

logger = logging.getLogger("trustlayer")


class PROVNClient:
    def __init__(self, api_key: str, base_url: str = "https://forma.2bd.net"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def send_run(self, run: "AgentRun") -> None:
        """Send run data to PROVN API in a background thread."""
        thread = threading.Thread(target=self._post_run, args=(run,), daemon=True)
        thread.start()

    def _post_run(self, run: "AgentRun") -> None:
        try:
            payload = json.dumps(run.to_dict(), default=str).encode("utf-8")
            req = urllib.request.Request(
                url=f"{self.base_url}/api/runs",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": self.api_key,
                    "Authorization": f"Bearer {self.api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status not in (200, 201):
                    logger.warning("PROVN API returned status %s", resp.status)
        except Exception as exc:
            logger.warning("Failed to send run to PROVN: %s", exc)

    def gate_check(
        self,
        agent_id: str,
        action_type: str,
        *,
        prompt: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Call the compliance gate synchronously before executing an action.
        Returns {"decision": "allow"|"warn"|"block", "reason": str, ...}

        This is a synchronous call (intentional — it must complete before the
        action proceeds). It typically returns within 5 ms since it runs
        locally on the API server with no external dependencies.

        On any network/timeout error, defaults to "allow" so the agent is
        never blocked by an infrastructure failure.
        """
        try:
            payload = json.dumps({
                "agent_id":    agent_id,
                "action_type": action_type,
                "prompt":      prompt,
                "tool_name":   tool_name,
                "tool_args":   tool_args,
            }, default=str).encode("utf-8")
            req = urllib.request.Request(
                url=f"{self.base_url}/api/gate/check",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": self.api_key,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            logger.debug("Gate check failed (allowing by default): %s", exc)
            return {"decision": "allow", "reason": "Gate unreachable — defaulting to allow.", "rule_id": None}
