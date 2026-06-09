"""Compliance gate — blocks non-compliant agent actions before they execute."""
from typing import Any, Dict, Optional


def check(
    agent_id: str,
    action_type: str = "llm_call",
    prompt: Optional[str] = None,
    raise_on_block: bool = True,
    metadata: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Check whether an action is allowed by the compliance gate.

    Returns the gate decision dict. If raise_on_block=True (default),
    raises ProvnGateBlock when decision == "block".

    Usage:
        provn.gate("agt_abc123", action_type="llm_call", prompt=user_input)
    """
    from provn import _client
    from provn.client import ProvnGateBlock

    if _client is None:
        return {"decision": "allow", "reason": "PROVN not initialised — gate skipped"}

    result = _client.check_gate(
        agent_id=agent_id,
        action_type=action_type,
        prompt=prompt,
        metadata=metadata,
    )

    if raise_on_block and result.get("decision") == "block":
        raise ProvnGateBlock(
            decision="block",
            reason=result.get("reason", "Blocked by compliance gate"),
            rule=result.get("rule_triggered", ""),
        )

    return result
