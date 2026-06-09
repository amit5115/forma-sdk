"""
PROVN SDK — AI Agent Governance in 3 lines.

    import provn

    provn.init(
        api_key="tl_live_...",
        human_sponsor="ops@company.com",
    )

    @provn.track
    def my_agent(task: str) -> str:
        # your existing code — unchanged
        return "done"

    my_agent("Hello from PROVN!")
"""
from __future__ import annotations

from typing import Optional

from provn.client import ProvnClient, ProvnAPIError, ProvnConnectionError, ProvnGateBlock
from provn.tracker import track, track_async, current_run
from provn import gate as _gate_module

__version__ = "0.6.0"
__all__ = [
    "init", "track", "track_async", "gate", "current_run",
    "ProvnClient", "ProvnAPIError", "ProvnConnectionError", "ProvnGateBlock",
]

_client: Optional[ProvnClient] = None


def init(
    api_key: str,
    human_sponsor: str = "",
    base_url: str = "https://api.provn.ai",
    timeout: int = 10,
) -> ProvnClient:
    """
    Initialise the PROVN SDK.

    Args:
        api_key:        Your PROVN API key (tl_live_...)
        human_sponsor:  Accountable human email — required for EU AI Act Art. 14
        base_url:       Override for self-hosted deployments
        timeout:        HTTP timeout in seconds (default 10)

    Returns:
        ProvnClient — also accessible globally after init()
    """
    global _client
    _client = ProvnClient(
        api_key=api_key,
        human_sponsor=human_sponsor,
        base_url=base_url,
        timeout=timeout,
    )
    return _client


def gate(
    agent_id: str,
    action_type: str = "llm_call",
    prompt: Optional[str] = None,
    raise_on_block: bool = True,
) -> dict:
    """
    Check the compliance gate before executing an action.

    Raises ProvnGateBlock if the action is blocked.

    Usage:
        provn.gate(agent_id, action_type="llm_call", prompt=user_input)
    """
    return _gate_module.check(
        agent_id=agent_id,
        action_type=action_type,
        prompt=prompt,
        raise_on_block=raise_on_block,
    )
