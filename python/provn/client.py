"""HTTP client for the PROVN API."""
import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


class ProvnClient:
    def __init__(
        self,
        api_key: str,
        human_sponsor: str = "",
        base_url: str = "https://api.provn.ai",
        timeout: int = 10,
    ):
        self.api_key = api_key
        self.human_sponsor = human_sponsor
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url=url,
            data=data,
            method=method,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.api_key,
                "User-Agent": "provn-python-sdk/0.6.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read().decode("utf-8"))
            except Exception:
                detail = {"detail": str(e)}
            raise ProvnAPIError(e.code, detail) from e
        except urllib.error.URLError as e:
            raise ProvnConnectionError(str(e)) from e

    # ── Run ingestion ─────────────────────────────────────────────────────────

    def submit_run(
        self,
        run_id: str,
        agent_name: str,
        agent_version: str,
        started_at: str,
        ended_at: Optional[str],
        duration_ms: Optional[int],
        status: str,
        steps: Optional[List[Dict]] = None,
        total_tokens: int = 0,
        total_cost_usd: float = 0.0,
        error: Optional[str] = None,
        signature: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        return self._request("POST", "/api/runs", {
            "run_id":         run_id,
            "agent_name":     agent_name,
            "agent_version":  agent_version,
            "human_sponsor":  self.human_sponsor,
            "started_at":     started_at,
            "ended_at":       ended_at,
            "duration_ms":    duration_ms,
            "status":         status,
            "steps":          steps or [],
            "total_tokens":   total_tokens,
            "total_cost_usd": total_cost_usd,
            "error":          error,
            "signature":      signature,
            "metadata":       metadata or {},
        })

    # ── Gate ──────────────────────────────────────────────────────────────────

    def check_gate(
        self,
        agent_id: str,
        action_type: str,
        prompt: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        return self._request("POST", "/api/gate/check", {
            "agent_id":    agent_id,
            "action_type": action_type,
            "prompt":      prompt,
            "metadata":    metadata or {},
        })

    # ── Kill switch ───────────────────────────────────────────────────────────

    def get_kill_status(self, agent_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/agents/{agent_id}/kill-status")

    # ── Agent ─────────────────────────────────────────────────────────────────

    def create_agent(
        self,
        name: str,
        version: str = "1.0.0",
        risk_class: str = "medium",
        description: str = "",
    ) -> Dict[str, Any]:
        return self._request("POST", "/api/agents", {
            "name":          name,
            "version":       version,
            "human_sponsor": self.human_sponsor,
            "risk_class":    risk_class,
            "description":   description,
        })

    def list_agents(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/api/agents")


class ProvnAPIError(Exception):
    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"PROVN API {status_code}: {detail}")


class ProvnConnectionError(Exception):
    pass


class ProvnGateBlock(Exception):
    """Raised by provn.gate() when an action is blocked by a compliance rule."""
    def __init__(self, decision: str, reason: str, rule: str = ""):
        self.decision = decision
        self.reason = reason
        self.rule = rule
        super().__init__(f"Gate blocked [{rule}]: {reason}")
