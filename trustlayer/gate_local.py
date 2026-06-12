"""
Local Enforcement Gate

In-process mirror of the server's compliance gate (api/app/services/gate.py).
The SDK fetches the agent's compiled policy bundle once (GET /api/gate/policy),
caches it, and evaluates every LLM/tool call locally in <1ms — no network hop
in the hot path. Decisions are batch-reported to POST /api/gate/log so the
audit trail and enforcement KPIs include every ALLOW/WARN/BLOCK.

Policy re-syncs every 60s in a background thread (piggybacks on the same
daemon-thread pattern as the kill-switch poller).
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from typing import Any, Dict, List, Optional

# ── PII patterns (mirror of server _PII_PATTERNS) ─────────────────────────────
_PII_PATTERNS: List[tuple] = [
    ("Aadhaar number",    re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
    ("Indian PAN",        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("Credit/Debit card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("SSN",               re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("Email address",     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b")),
    ("Phone number",      re.compile(r"\b(?:\+?91[\-\s]?)?[6-9]\d{9}\b")),
    ("IBAN",              re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b")),
    ("Passport number",   re.compile(r"\b[A-Z]\d{7}\b")),
]

# ── Injection patterns (mirror of server _INJECTION_PATTERNS) ─────────────────
_INJECTION_PATTERNS: List[tuple] = [
    ("prompt injection (ignore safety)",   re.compile(r"(?i)ignore\s.{0,40}(safety|constraint|guard|rule|policy|previous|instruction|system)")),
    ("prompt injection (override/bypass)", re.compile(r"(?i)(jailbreak|bypass|disable|override|circumvent)\s.{0,40}(safety|constraint|filter|guard|policy|system|rule)")),
    ("credential extraction",              re.compile(r"(?i)(reveal|expose|dump|show|leak|exfiltrate)\s.{0,40}(password|secret|api.?key|credential|token|key)")),
    ("role-switching attack",              re.compile(r"(?i)(you are now|act as|pretend to be|roleplay as|switch to)\s.{0,40}(admin|root|unrestricted|jailbreak|DAN|god mode)")),
    ("system prompt extraction",           re.compile(r"(?i)(print|output|repeat|show|tell me)\s.{0,30}(your\s)?(system\s)?prompt|instruction")),
]


def _detect_pii(text: str) -> Optional[str]:
    for label, pattern in _PII_PATTERNS:
        if pattern.search(text):
            return label
    return None


def evaluate_local(
    policy: Dict[str, Any],
    *,
    action_type: str,
    prompt: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_args: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluate an action against a cached policy bundle.
    Returns {"decision": "allow"|"warn"|"block", "reason": str, "rule_id": str|None}
    """
    # 1. Kill switch
    if policy.get("kill_active"):
        return {"decision": "block", "rule_id": "kill_switch",
                "reason": "Agent has an active kill switch. All actions blocked."}

    # 2. Tool authorization
    authorized = policy.get("authorized_actions")
    if action_type == "tool_call" and tool_name and authorized:
        if tool_name not in authorized:
            return {"decision": "block", "rule_id": "unauthorized_tool",
                    "reason": f"Tool '{tool_name}' is not in this agent's authorized actions list."}

    # 3. Prompt injection (always on)
    if policy.get("injection_check", True) and action_type == "llm_call" and prompt:
        for label, pattern in _INJECTION_PATTERNS:
            if pattern.search(prompt):
                return {"decision": "block", "rule_id": "prompt_injection",
                        "reason": f"Prompt injection attempt detected: {label}. Blocked by FORMA Gate."}

    # 4. PII (when an enforced framework requires it)
    if policy.get("pii_check"):
        if action_type == "llm_call" and prompt:
            pii = _detect_pii(prompt)
            if pii:
                return {"decision": "block", "rule_id": "pii_in_prompt",
                        "reason": f"PII detected in LLM prompt: {pii}. Blocked by FORMA Gate "
                                  f"({', '.join(policy.get('frameworks', [])) or 'PII protection'})."}
        if action_type == "tool_call" and tool_args:
            pii = _detect_pii(json.dumps(tool_args, default=str))
            if pii:
                return {"decision": "block", "rule_id": "pii_in_tool_args",
                        "reason": f"PII detected in tool arguments: {pii}. Blocked by FORMA Gate."}

    # 5. Custom / pack rules
    warn: Optional[Dict[str, Any]] = None
    for rule in policy.get("rules", []):
        if not rule.get("enabled", True):
            continue
        target = ""
        field = rule.get("field", "prompt")
        if field == "prompt" and prompt:
            target = prompt
        elif field == "tool_name" and tool_name:
            target = tool_name
        elif field == "tool_args" and tool_args:
            target = json.dumps(tool_args, default=str)
        if not target:
            continue
        try:
            if re.search(rule.get("pattern", ""), target, re.IGNORECASE):
                detail = rule.get("message") or f"Rule '{rule.get('id')}' matched on {field}."
                if rule.get("action", "block") == "block":
                    return {"decision": "block", "rule_id": rule.get("id"), "reason": detail}
                warn = {"decision": "warn", "rule_id": rule.get("id"), "reason": detail}
        except re.error:
            continue

    if warn:
        return warn
    return {"decision": "allow", "rule_id": None,
            "reason": "Action permitted — all compliance checks passed."}


# ── Bootstrap policy (instant local enforcement before server sync) ───────────

_PACK_FLAGS = {
    "dpdp": "dpdp", "dpdp_act": "dpdp", "dpdp_act_2023": "dpdp",
    "rbi": "rbi", "rbi_ml_risk": "rbi", "rbi_mrm": "rbi",
    "eu_ai_act": "eu_ai_act", "euaiact": "eu_ai_act",
    "iso42001": "iso42001", "iso_42001": "iso42001",
    "gdpr": "gdpr",
}
_PII_FLAG_SET = {"dpdp", "eu_ai_act", "gdpr"}


def bootstrap_policy(agent_name: str, packs: List[str]) -> Dict[str, Any]:
    """
    Minimal local policy active immediately when enforce=[...] is declared,
    before the first server sync completes. Covers the built-in PII and
    injection checks; pack/custom rules arrive with the server bundle.
    """
    flags = sorted({
        _PACK_FLAGS.get(str(p).strip().lower().replace("-", "_"), str(p).lower())
        for p in packs
    })
    return {
        "agent_id": agent_name,
        "agent_name": agent_name,
        "registered": True,           # local bootstrap counts as active
        "bootstrap": True,
        "kill_active": None,
        "frameworks": flags,
        "enforce_packs": list(packs),
        "pii_check": bool(set(flags) & _PII_FLAG_SET),
        "injection_check": True,
        "authorized_actions": None,
        "rules": [],
        "version": "bootstrap",
    }


# ── Policy cache + background sync + decision reporter ────────────────────────

class PolicyCache:
    """
    Per-process policy store. One entry per agent name.
    Sync thread refreshes all registered policies every `sync_interval` seconds.
    Blocked/warned/allowed decisions are buffered and batch-flushed to the API.
    """

    def __init__(self, client, sync_interval: int = 60, flush_interval: int = 10):
        self._client = client
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._pending_packs: Dict[str, List[str]] = {}
        self._lock = threading.Lock()
        self._decisions: List[Dict[str, Any]] = []
        self._sync_interval = sync_interval
        self._flush_interval = flush_interval
        self._started = False

    def get(self, agent_name: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._policies.get(agent_name)

    def register(self, agent_name: str, enforce_packs: Optional[List[str]] = None):
        """
        Start enforcing for an agent. If packs are given, a local bootstrap
        policy takes effect immediately (PII + injection checks) so blocking
        works from the very first call; the full server policy (including
        pack rules and custom rules) replaces it on first successful sync.
        """
        if enforce_packs:
            with self._lock:
                self._pending_packs[agent_name] = list(enforce_packs)
                if agent_name not in self._policies:
                    self._policies[agent_name] = bootstrap_policy(agent_name, enforce_packs)

        def _setup():
            self._sync_one(agent_name)
        threading.Thread(target=_setup, daemon=True).start()
        self._ensure_threads()

    def _sync_one(self, agent_name: str):
        """Apply pending packs (retried until the agent exists), then refresh policy."""
        try:
            with self._lock:
                packs = self._pending_packs.get(agent_name)
            if packs:
                applied = self._client.apply_policy(agent_name, packs)
                if applied is not None:
                    with self._lock:
                        self._pending_packs.pop(agent_name, None)
            policy = self._client.get_policy(agent_name)
            if policy and policy.get("registered"):
                with self._lock:
                    self._policies[agent_name] = policy
        except Exception:
            pass

    def check(
        self,
        agent_name: str,
        *,
        action_type: str,
        prompt: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Local gate check. Returns the decision dict, or None when no policy
        is cached yet (caller decides whether to fall back to server check).
        Every decision is buffered for batch reporting.
        """
        policy = self.get(agent_name)
        if policy is None or not policy.get("registered", True):
            return None
        result = evaluate_local(
            policy, action_type=action_type,
            prompt=prompt, tool_name=tool_name, tool_args=tool_args,
        )
        entry = {
            "agent_id": policy.get("agent_id") or agent_name,
            "action_type": action_type,
            "decision": result["decision"],
            "rule_id": result.get("rule_id"),
            "reason": result.get("reason"),
            "tool_name": tool_name,
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16] if prompt else None,
        }
        with self._lock:
            self._decisions.append(entry)
        if result["decision"] == "block":
            self._flush_now()       # blocks are reported immediately
        return result

    # ── internals ──────────────────────────────────────────────────────────────

    def _ensure_threads(self):
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._sync_loop, daemon=True).start()
        threading.Thread(target=self._flush_loop, daemon=True).start()

    def _sync_loop(self):
        while True:
            time.sleep(self._sync_interval)
            with self._lock:
                names = set(self._policies.keys()) | set(self._pending_packs.keys())
            for name in names:
                self._sync_one(name)

    def _flush_loop(self):
        while True:
            time.sleep(self._flush_interval)
            self._flush_now()

    def _flush_now(self):
        with self._lock:
            batch = list(self._decisions)
            self._decisions.clear()
        if batch:
            try:
                self._client.log_gate_decisions(batch)
            except Exception:
                pass


# ── Process-wide shared cache (used by tracker + auto-capture patches) ────────

_shared_cache: Optional[PolicyCache] = None
_shared_lock = threading.Lock()


def get_shared_cache(client=None) -> Optional[PolicyCache]:
    """
    Return the process-wide PolicyCache, creating it on first call with a
    client. Returns None if never initialized (no enforcement configured).
    """
    global _shared_cache
    with _shared_lock:
        if _shared_cache is None and client is not None:
            _shared_cache = PolicyCache(client)
        return _shared_cache
