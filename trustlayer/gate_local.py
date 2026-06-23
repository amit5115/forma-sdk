"""
Local Enforcement Gate

In-process mirror of the server's compliance gate (api/app/services/gate.py).
The SDK fetches the agent's compiled policy bundle once (GET /api/gate/policy),
caches it, and evaluates every LLM/tool call locally in <1ms — no network hop
in the hot path. Decisions are batch-reported to POST /api/gate/log so the
audit trail and enforcement KPIs include every ALLOW/WARN/BLOCK.

Policy re-syncs every 60s in a background thread (piggybacks on the same
daemon-thread pattern as the kill-switch poller).

v2.3.0 additions:
  - _SyncCircuitBreaker: stops retrying sync after 5 consecutive failures
  - Disk-backed decision buffer: unflushed decisions survive crashes
  - Per-rule decision counters + PolicyCache.stats()
  - HMAC-signed decision entries + PolicyCache.verify_log()
  - Expanded PII patterns: GSTIN, IFSC, DL, DoB, Visa/MC/Amex
"""
from __future__ import annotations
import hashlib
import hmac
import json
import logging
import pathlib
import re
import threading
import time
from typing import Any, Dict, List, Optional

# ── Multi-layer threat engine (vendored mirror of the server engine) ──────────
# Gives the local gate the same jailbreak/injection coverage as the server
# (semantic variants, obfuscation, de-leetspeak). If the import ever fails the
# gate degrades gracefully to the legacy regex list below — fail-safe, never
# fail-open silently on an import error.
try:
    from . import threat_engine as _threat_engine
    _HAS_THREAT_ENGINE = True
except Exception:  # pragma: no cover - defensive
    _threat_engine = None
    _HAS_THREAT_ENGINE = False

# Canonical decision-content fields covered by the tamper-evidence HMAC
# signature. Excludes agent_id (the server resolves name → internal id on
# ingest) and the server-added id/created_at, so a signature computed locally
# still verifies after a round-trip through GET /api/gate/log. The SDK signer
# (_sign_entry) and the CLI verifier (verify-decisions) MUST use this exact set.
_SIGNED_FIELDS = ("action_type", "decision", "rule_id", "reason", "tool_name", "prompt_hash")

# ── PII patterns (mirror of server api/app/services/gate.py _PII_PATTERNS) ───
# Keep this list in sync with the server's gate.py.
_PII_PATTERNS: List[tuple] = [
    # Core India PII
    # Covers: space/comma/dot/slash-separated Aadhaar. Deliberately excludes dash
    # (4111-2023-0001 is structurally identical to 2341-1234-1236 — can't distinguish).
    # Real Aadhaar attack vectors use spaces, commas, dots; dash is ambiguous.
    ("Aadhaar number",    re.compile(
        r"\b(?:"
        r"\d{4}[\s,./]?\d{4}[\s,./]?\d{4}"   # 4-4-4 with space/comma/dot/slash
        r"|"
        r"\d(?:[\s,.]\d){11}"                  # every-digit-spaced: 2 3 4 1 1 2 3 4 1 2 3 6
        r")\b"
    )),
    ("Indian PAN",        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("SSN",               re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("Email address",     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b")),
    ("Phone number",      re.compile(r"\b(?:\+?91[\-\s]?)?[6-9]\d{4}[\s\-]?\d{5}\b")),

    # India-specific additions (DPDP moat)
    ("GSTIN",             re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b")),
    ("UPI ID",            re.compile(
        r"\b[a-zA-Z0-9][a-zA-Z0-9.\-_]{1,98}@"
        r"(?:ok[a-z]+|paytm|ybl|apl|upi|ibl|axl|sbi|hdfcbank|hdfc|icici|axisbank|axis|"
        r"kotak|fbl|yapl|jupiteraxis|barodampay|airtel|jio|freecharge|cnrb|idfcfirst|"
        r"dbs|indus|abfspay|kbl|federal|pingpay|naviaxis|rmhdfc|waaxis|yesg|timecosmos)\b",
        re.IGNORECASE)),
    ("Indian Passport",   re.compile(r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b")),
    ("IFSC code",         re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")),
    ("Driving License",   re.compile(r"\bDL[-\s]?\d{13}\b", re.IGNORECASE)),
    ("Date of birth",     re.compile(r"(?:dob|date[\s._-]?of[\s._-]?birth)[:\s]*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}", re.IGNORECASE)),

    # Credit / debit cards — require digits and optional spaces only (no dashes that indicate ref numbers)
    ("Visa card",         re.compile(r"(?<![0-9\-])4[0-9]{3}[\s]?[0-9]{4}[\s]?[0-9]{4}[\s]?[0-9]{1,4}(?![0-9\-])")),
    ("Mastercard",        re.compile(r"(?<![0-9\-])5[1-5][0-9]{2}[\s]?[0-9]{4}[\s]?[0-9]{4}[\s]?[0-9]{4}(?![0-9\-])")),
    ("Amex",              re.compile(r"(?<![0-9\-])3[47][0-9]{2}[\s]?[0-9]{6}[\s]?[0-9]{5}(?![0-9\-])")),
    ("CVV",               re.compile(r"(?:cvv|cvc|security[\s._-]?code)\D{0,15}\d{3,4}", re.IGNORECASE)),
    # Generic card fallback — only spaces allowed as separators (not dashes, which indicate ref numbers)
    ("Credit/Debit card", re.compile(r"\b(?:\d\s?){13,16}\b")),

    # International
    ("IBAN",              re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("Passport number",   re.compile(r"\b[A-Z]\d{7}\b")),
]

# ── Injection patterns (legacy fallback when threat_engine unavailable) ────────
_INJECTION_PATTERNS: List[tuple] = [
    ("prompt injection (ignore safety)",   re.compile(r"(?i)ignore\s.{0,40}(safety|constraint|guard|rule|policy|previous|instruction|system)")),
    ("prompt injection (override/bypass)", re.compile(r"(?i)(jailbreak|bypass|disable|override|circumvent)\s.{0,40}(safety|constraint|filter|guard|policy|system|rule)")),
    ("credential extraction",              re.compile(r"(?i)(reveal|expose|dump|show|leak|exfiltrate)\s.{0,40}(password|secret|api.?key|credential|token|key)")),
    ("role-switching attack",              re.compile(r"(?i)(you are now|act as|pretend to be|roleplay as|switch to)\s.{0,40}(admin|root|unrestricted|jailbreak|DAN|god mode)")),
    ("system prompt extraction",           re.compile(r"(?i)(print|output|repeat|show|tell me)\s.{0,30}(your\s)?(system\s)?prompt|instruction")),
]


# ── India identifier checksum validators (DPDP moat) ──────────────────────────
# These do NOT gate blocking — a regex match alone still blocks (fail-safe: a
# typo'd or deliberately-obfuscated Aadhaar should still be stopped). A passing
# checksum upgrades the label to "(verified)" so the audit trail / Playground can
# show that FORMA validated a REAL government identifier, not just a number shape.
# Keep identical to api/app/services/gate.py.

# Verhoeff dihedral-group tables (used by the Aadhaar 12-digit check digit).
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 9, 1, 2, 3, 4, 6, 7), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_GST_CODEPOINTS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def aadhaar_is_valid(value: str) -> bool:
    """True if the 12 digits in `value` pass the Verhoeff check (real Aadhaar)."""
    digits = re.sub(r"\D", "", value or "")
    if len(digits) != 12 or digits[0] in "01":
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def gstin_is_valid(value: str) -> bool:
    """True if `value` is a structurally + checksum valid 15-char GSTIN."""
    g = (value or "").strip().upper()
    if len(g) != 15:
        return False
    factor, total, n = 2, 0, len(_GST_CODEPOINTS)
    try:
        for ch in reversed(g[:14]):
            cp = _GST_CODEPOINTS.index(ch) * factor
            total += cp // n + cp % n
            factor = 1 if factor == 2 else 2
    except ValueError:
        return False
    return _GST_CODEPOINTS[(n - total % n) % n] == g[14]


def _normalize(text: str) -> str:
    """Unicode NFKD normalization + homoglyph de-obfuscation.

    Attackers use Cyrillic/Greek lookalike chars (І vs I, р vs p, і vs i) to
    bypass regex-based injection detection. NFKD decomposes them; then we strip
    non-ASCII after decomposition so Cyrillic Cyrillic 'І' (U+0406) becomes empty
    rather than being treated as a safe char. This is defense-in-depth on top of
    the threat engine's own de-obfuscation layer.
    """
    import unicodedata
    # NFKD normalization: decomposes compatibility chars
    nfkd = unicodedata.normalize("NFKD", text)
    # Replace common homoglyphs that survive NFKD with their ASCII equivalents
    _HOMOGLYPHS = {
        "І": "I", "і": "i", "ІС": "IS", "Ꭵ": "i",
        "р": "p", "Р": "P", "а": "a", "А": "A",
        "е": "e", "Е": "E", "о": "o", "О": "O",
        "с": "c", "С": "C", "х": "x", "Х": "X",
        "ѕ": "s", "ν": "v", "ɑ": "a", "ɡ": "g",
    }
    for cyrillic, latin in _HOMOGLYPHS.items():
        nfkd = nfkd.replace(cyrillic, latin)
    return nfkd


def _detect_pii(text: str) -> Optional[str]:
    text = _normalize(text)
    for label, pattern in _PII_PATTERNS:
        m = pattern.search(text)
        if m:
            if label == "Aadhaar number" and aadhaar_is_valid(m.group()):
                return "Aadhaar number (Verhoeff-verified)"
            if label == "GSTIN" and gstin_is_valid(m.group()):
                return "GSTIN (checksum-verified)"
            return label
    return None


def _injection_check(
    text: str, *, action_type: str, tool_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    text = _normalize(text)  # homoglyph de-obfuscation before scan
    """
    Run the multi-layer threat engine over `text`, returning a block/warn
    decision dict, or None when the text is clean. Falls back to the legacy
    regex list if the bundled engine is unavailable or errors (fail-safe).

    APPROVAL is treated as a hard block locally (fail-closed): nothing in the
    SDK hot path can route to a human inline, so a bare "approval" must not
    fail open — mirrors the server's gate.py mapping.
    """
    if _HAS_THREAT_ENGINE:
        try:
            det = _threat_engine.detect(
                text, context={"action_type": action_type, "tool_name": tool_name},
            )
            rule_id = f"threat_{(det.category or 'injection').lower()}"
            if det.action in ("BLOCK", "APPROVAL"):
                return {"decision": "block", "rule_id": rule_id, "reason": det.reason}
            if det.action == "WARN":
                return {"decision": "warn", "rule_id": rule_id, "reason": det.reason}
            return None
        except Exception:
            pass  # any engine error → fall through to the legacy patterns
    for label, pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return {"decision": "block", "rule_id": "prompt_injection",
                    "reason": f"Prompt injection attempt detected: {label}. Blocked by FORMA Gate."}
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
    if action_type == "tool_call" and tool_name and authorized is not None:
        if tool_name not in authorized:
            return {"decision": "block", "rule_id": "unauthorized_tool",
                    "reason": f"Tool '{tool_name}' is not in this agent's authorized actions list."}

    # 3. Prompt-injection / jailbreak (always on) — multi-layer engine, run on
    #    the LLM prompt AND on tool-call arguments (parity with the server gate,
    #    so an encoded payload smuggled through tool args is caught too).
    warn: Optional[Dict[str, Any]] = None
    if policy.get("injection_check", True):
        scan_text: Optional[str] = None
        if action_type == "llm_call" and prompt:
            scan_text = prompt
        elif action_type == "tool_call":
            # Scan both the prompt text and serialized tool_args so that
            # tl.preview("drop tables", action_type="tool_call") works as documented.
            parts = []
            if prompt:
                parts.append(prompt)
            if tool_args:
                parts.append(json.dumps(tool_args, default=str))
            scan_text = " ".join(parts) if parts else None
        if scan_text:
            verdict = _injection_check(scan_text, action_type=action_type, tool_name=tool_name)
            if verdict is not None:
                if verdict["decision"] == "block":
                    return verdict
                warn = verdict   # WARN — remember it, but keep evaluating other layers

    # 4. PII (when an enforced framework requires it)
    if policy.get("pii_check"):
        if action_type == "llm_call" and prompt:
            pii = _detect_pii(prompt)
            if pii:
                return {"decision": "block", "rule_id": "pii_in_prompt",
                        "reason": f"PII detected in LLM prompt: {pii}. Blocked by FORMA Gate "
                                  f"({', '.join(policy.get('frameworks', [])) or 'PII protection'})."}
        if action_type == "tool_call":
            tool_call_text_parts = []
            if prompt:
                tool_call_text_parts.append(prompt)
            if tool_args:
                tool_call_text_parts.append(json.dumps(tool_args, default=str))
            tool_call_text = " ".join(tool_call_text_parts)
            if tool_call_text:
                pii = _detect_pii(tool_call_text)
                if pii:
                    return {"decision": "block", "rule_id": "pii_in_tool_args",
                            "reason": f"PII detected in tool call: {pii}. Blocked by FORMA Gate."}

    # 5. Custom / pack rules
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
# Packs whose bootstrap policy activates the broad PII layer (Aadhaar/PAN/card/
# phone/email). hipaa + pci_dss are PII/PHI-centric and their pack metadata
# advertises "PII in LLM prompt → BLOCK" — they MUST be here or enforce=["hipaa"]
# / enforce=["pci_dss"] silently allows PII through. Keep in sync with the server
# sets (services/gate.py::_PII_FRAMEWORKS and routers/gate.py bundle builder).
_PII_FLAG_SET = {"ai_safety", "dpdp", "eu_ai_act", "gdpr", "hipaa", "pci_dss"}


def bootstrap_policy(
    agent_name: str,
    packs: List[str],
    *,
    authorized_actions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Minimal local policy active immediately when enforce=[...] is declared,
    before the first server sync completes. Covers the built-in PII and
    injection checks; pack/custom rules arrive with the server bundle.

    ``authorized_actions`` (from tl.init/tl.using) lets the local gate deny any
    tool call whose name is not in the allow-list, with no decorator.
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
        "authorized_actions": list(authorized_actions) if authorized_actions is not None else None,
        "rules": [],
        "version": "bootstrap",
    }


# ── Sync circuit breaker ──────────────────────────────────────────────────────

class _SyncCircuitBreaker:
    """
    Stops hammering the API after 5 consecutive sync failures.
    Auto-resets after 5 minutes of silence so a server restart is detected.
    Prevents log spam and shows production-grade resilience.
    """

    def __init__(self, threshold: int = 5, reset_window: int = 300):
        self._failures = 0
        self._threshold = threshold
        self._open = False
        self._last_failure = 0.0
        self._reset_window = reset_window

    def record_failure(self) -> None:
        self._failures += 1
        self._last_failure = time.time()
        if self._failures >= self._threshold:
            if not self._open:
                logging.getLogger(__name__).warning(
                    "[FORMA] Policy sync circuit breaker OPEN after %d consecutive failures — "
                    "bootstrap policy stays active. Check API connectivity.",
                    self._failures,
                )
            self._open = True

    def record_success(self) -> None:
        if self._open:
            logging.getLogger(__name__).info(
                "[FORMA] Policy sync circuit breaker CLOSED — server policy restored."
            )
        self._failures = 0
        self._open = False

    @property
    def is_open(self) -> bool:
        if self._open and (time.time() - self._last_failure > self._reset_window):
            self._open = False
            self._failures = 0
        return self._open


# ── Disk-backed decision buffer ───────────────────────────────────────────────

_PENDING_DIR = pathlib.Path.home() / ".forma"
# Legacy un-scoped path (pre-2.3.7). Kept only so an upgrading process can clean
# it up — never loaded into a cache, since its key/org is unknown.
_PENDING_FILE = _PENDING_DIR / "pending_decisions.jsonl"


def _pending_file(api_key: Optional[str]) -> pathlib.Path:
    """
    Per-key buffer path. Decisions are scoped to the api_key that produced them
    so a process using one org's key never loads + flushes another org's
    persisted decisions under its own credentials (cross-tenant leak). The key
    itself is never written to disk — only a short non-reversible hash of it.
    """
    keyhash = hashlib.sha256((api_key or "anon").encode("utf-8")).hexdigest()[:16]
    return _PENDING_DIR / f"pending_decisions_{keyhash}.jsonl"


def _persist_batch(entries: List[Dict], api_key: Optional[str] = None) -> None:
    """Append undelivered decisions to a key-scoped file so they survive a crash."""
    try:
        path = _pending_file(api_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            for e in entries:
                fh.write(json.dumps(e, default=str) + "\n")
    except Exception as _exc:
        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)


def _load_persisted(api_key: Optional[str] = None) -> List[Dict]:
    """Load and clear decisions persisted by a previous run of THIS api_key."""
    try:
        path = _pending_file(api_key)
        if path.exists():
            lines = path.read_text().splitlines()
            data = [json.loads(line) for line in lines if line.strip()]
            path.unlink()
            return data
    except Exception as _exc:
        logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
    return []


# ── Policy cache + background sync + decision reporter ────────────────────────

class PolicyCache:
    """
    Per-process policy store. One entry per agent name.
    Sync thread refreshes all registered policies every `sync_interval` seconds.
    Blocked/warned/allowed decisions are buffered and batch-flushed to the API.

    v2.3.0: circuit breaker stops sync after 5 failures; decisions are HMAC-
    signed before reporting (tamper-evident audit trail); unflushed decisions
    are persisted to disk on flush failure; per-rule counters power tl.status().
    """

    def __init__(self, client, sync_interval: int = 60, flush_interval: int = 10):
        self._client = client
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._pending_packs: Dict[str, List[str]] = {}
        # Per-agent authorized-action allow-lists (from enforce + authorized_actions),
        # re-applied after every server sync so the allow-list is never dropped.
        self._authorized_actions: Dict[str, List[str]] = {}
        # Process-wide fallback policy (set by tl.init(enforce=[...])). Applies
        # to every agent that has no explicitly-registered policy of its own,
        # so init-level enforcement is genuinely process-wide.
        self._default_policy: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()
        self._sync_interval = sync_interval
        self._flush_interval = flush_interval
        self._started = False
        # Set by check() on a block so the background flush loop reports it
        # immediately — WITHOUT doing the network POST on the caller's thread
        # (a synchronous flush here froze the user's request for the full HTTP
        # timeout whenever the API was slow/unreachable).
        self._flush_signal = threading.Event()
        # Set by shutdown() (on re-init) so the sync + flush loops exit instead of
        # leaking as orphaned daemon threads that poll the API forever.
        self._stop_event = threading.Event()

        # v2.3.0: per-rule decision counters (keys match evaluate_local decision values)
        self._counters: Dict[str, int] = {"total": 0, "block": 0, "warn": 0, "allow": 0}
        self._rule_hits: Dict[str, int] = {}
        self._last_sync: Optional[float] = None

        # v2.3.0: circuit breaker for policy sync
        self._breaker = _SyncCircuitBreaker()

        # v2.3.0: decision buffer (load any decisions persisted from previous run).
        # Scoped to this client's api_key so we never adopt another org's
        # persisted decisions (cross-tenant leak fixed in 2.3.7).
        persisted = _load_persisted(getattr(client, "api_key", None))
        self._decisions: List[Dict[str, Any]] = persisted

    def get(self, agent_name: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._policies.get(agent_name)

    def register(
        self,
        agent_name: str,
        enforce_packs: Optional[List[str]] = None,
        *,
        authorized_actions: Optional[List[str]] = None,
    ):
        """
        Start enforcing for an agent. If packs are given, a local bootstrap
        policy takes effect immediately (PII + injection checks) so blocking
        works from the very first call; the full server policy (including
        pack rules and custom rules) replaces it on first successful sync.

        ``authorized_actions`` (from enforce + tl.init/tl.register) is stored
        per-agent and re-applied after every server sync so the tool allow-list
        is enforced on this agent's own policy, not just the process default.
        """
        if authorized_actions is not None:
            with self._lock:
                self._authorized_actions[agent_name] = list(authorized_actions)

        # Read `already_registered` INSIDE the lock so concurrent first-time
        # registrations don't all see False, then each spawn their own sync thread.
        already_registered = False
        if enforce_packs:
            with self._lock:
                already_registered = agent_name in self._policies
                self._pending_packs[agent_name] = list(enforce_packs)
                if not already_registered:
                    self._policies[agent_name] = bootstrap_policy(
                        agent_name, enforce_packs,
                        authorized_actions=self._authorized_actions.get(agent_name),
                    )
        else:
            with self._lock:
                already_registered = agent_name in self._policies

        # Only start a background sync thread on first registration.
        # Subsequent calls (e.g. from _using_cm on every function invocation)
        # are no-ops once the policy is in place — avoids thread-per-call overhead.
        if not already_registered:
            def _setup():
                self._sync_one(agent_name)
            threading.Thread(target=_setup, daemon=True).start()
        self._ensure_threads()

    def register_default(
        self,
        enforce_packs: Optional[List[str]] = None,
        *,
        authorized_actions: Optional[List[str]] = None,
    ):
        """
        Set a process-wide enforcement policy applied to EVERY agent that does
        not have its own explicitly-registered policy. This makes
        ``tl.init(enforce=[...])`` genuinely process-wide: PII and prompt
        injection are blocked locally on every LLM/tool call, regardless of the
        agent name used. A per-scope ``tl.using(enforce=[...])`` policy still
        takes precedence for that agent.
        """
        if not enforce_packs:
            return
        with self._lock:
            self._default_policy = bootstrap_policy(
                "*", enforce_packs, authorized_actions=authorized_actions,
            )
        self._ensure_threads()

    def _sync_one(self, agent_name: str) -> None:
        """Apply pending packs (retried until the agent exists), then refresh policy."""
        if self._breaker.is_open:
            return  # circuit open — skip until auto-reset
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
                    # Preserve the locally-configured tool allow-list — the
                    # server bundle may not carry authorized_actions.
                    authz = self._authorized_actions.get(agent_name)
                    if authz is not None and not policy.get("authorized_actions"):
                        policy["authorized_actions"] = list(authz)
                    self._policies[agent_name] = policy
                    self._last_sync = time.time()
                self._breaker.record_success()
        except Exception as _exc:
            logging.getLogger(__name__).debug("suppressed exception: %s", _exc)
            self._breaker.record_failure()

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
        Every decision is buffered for batch reporting (HMAC-signed).
        """
        policy = self.get(agent_name)
        if policy is None:
            # Fall back to the process-wide default (tl.init(enforce=[...])).
            policy = self._default_policy
        if policy is None or not policy.get("registered", True):
            return None
        result = evaluate_local(
            policy, action_type=action_type,
            prompt=prompt, tool_name=tool_name, tool_args=tool_args,
        )

        # v2.3.0: update per-rule counters
        decision = result.get("decision", "allow")
        with self._lock:
            self._counters["total"] += 1
            self._counters[decision] = self._counters.get(decision, 0) + 1
            rid = result.get("rule_id")
            if rid:
                self._rule_hits[rid] = self._rule_hits.get(rid, 0) + 1

        entry = {
            "agent_id": agent_name,
            "action_type": action_type,
            "decision": decision,
            "rule_id": result.get("rule_id"),
            "reason": result.get("reason"),
            "tool_name": tool_name,
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16] if prompt else None,
        }
        # v2.3.0: sign the entry before queuing
        entry = self._sign_entry(entry)
        with self._lock:
            self._decisions.append(entry)
        if result["decision"] == "block":
            # Report blocks immediately, but never on the caller's thread: wake
            # the background flush loop instead. A synchronous POST here froze
            # the user's request for the full HTTP timeout (~30s) whenever the
            # API was slow or unreachable — defeating the <1ms local-gate promise.
            self._ensure_threads()      # idempotent — guarantees the loop exists
            self._flush_signal.set()
        return result

    # ── v2.3.0 new methods ─────────────────────────────────────────────────────

    def _sign_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """HMAC-SHA256 sign a gate decision entry for tamper-evidence.

        Signs only the canonical decision-content fields (``_SIGNED_FIELDS``) so
        the signature survives a round-trip through the API: the server resolves
        ``agent_id`` (name → internal id) on ingest and adds ``id``/``created_at``,
        none of which are part of the signature. ``trustlayer verify-decisions``
        recomputes the HMAC over the same field set, so signatures verify
        end-to-end (previously the whole entry was signed, so the server's
        agent_id rewrite made every fetched decision fail verification)."""
        try:
            payload = json.dumps(
                {k: entry.get(k) for k in _SIGNED_FIELDS},
                sort_keys=True, separators=(",", ":"), default=str,
            )
            sig = hmac.new(
                self._client.api_key.encode("utf-8"),
                payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            return {**entry, "_sig": f"hmac-sha256:{sig}"}
        except Exception:
            return entry  # never fail the gate check due to signing

    def verify_log(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Verify HMAC signatures on a list of gate decision entries.
        Returns {verified: bool, passed: int, failed: int, unsigned: int}.
        """
        passed = failed = unsigned = 0
        for e in entries:
            if "_sig" not in e:
                unsigned += 1
                continue
            expected = self._sign_entry({k: v for k, v in e.items() if k != "_sig"}).get("_sig", "")
            if hmac.compare_digest(e["_sig"], expected):
                passed += 1
            else:
                failed += 1
        return {"verified": failed == 0, "passed": passed, "failed": failed, "unsigned": unsigned}

    def stats(self) -> Dict[str, Any]:
        """
        Return real-time enforcement stats: decision counts, top rule hits,
        sync status, and circuit breaker state.
        """
        with self._lock:
            top_rules = sorted(self._rule_hits.items(), key=lambda x: -x[1])[:5]
            return {
                "decisions": dict(self._counters),
                "top_rule_hits": dict(top_rules),
                "policies_cached": list(self._policies.keys()),
                "last_sync": self._last_sync,
                "circuit_breaker_open": self._breaker.is_open,
            }

    # ── internals ──────────────────────────────────────────────────────────────

    def _ensure_threads(self) -> None:
        # Check-then-act under the lock so concurrent callers don't each start
        # an extra pair of sync/flush threads before self._started is set.
        with self._lock:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._sync_loop, daemon=True).start()
        threading.Thread(target=self._flush_loop, daemon=True).start()

    def _sync_loop(self) -> None:
        # _stop_event.wait() returns True the moment shutdown() is called, so a
        # re-init (new tl.init()) doesn't leave this thread polling the API forever.
        while not self._stop_event.wait(self._sync_interval):
            if self._breaker.is_open:
                continue  # circuit open — wait for auto-reset
            with self._lock:
                names = set(self._policies.keys()) | set(self._pending_packs.keys())
            for name in names:
                self._sync_one(name)

    def _flush_loop(self) -> None:
        while True:
            # Wake early when a block sets the signal OR when shutdown() sets it;
            # otherwise flush on the interval. The network POST happens here, on
            # this background thread — never on the caller's request thread.
            self._flush_signal.wait(self._flush_interval)
            self._flush_signal.clear()
            self._flush_now()
            if self._stop_event.is_set():
                return  # flushed remaining decisions, now exit (re-init / shutdown)

    def shutdown(self) -> None:
        """
        Stop this cache's background sync + flush threads (one final flush first).

        Called on re-init so a replaced PolicyCache doesn't leak two daemon threads
        that keep syncing policy + flushing decisions to the API forever. Idempotent
        and best-effort — never raises.
        """
        self._stop_event.set()
        self._flush_signal.set()   # wake the flush loop so it exits promptly

    def _flush_now(self) -> None:
        with self._lock:
            batch = list(self._decisions)
            self._decisions.clear()
        if batch:
            try:
                self._client.log_gate_decisions(batch)
            except Exception as _exc:
                logging.getLogger(__name__).debug(
                    "Gate decision flush failed — persisting %d entries to disk: %s",
                    len(batch), _exc,
                )
                # v2.3.0: persist to disk so decisions survive process restart
                # (key-scoped since 2.3.7 — see _pending_file).
                _persist_batch(batch, getattr(self._client, "api_key", None))


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
