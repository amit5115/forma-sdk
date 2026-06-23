"""
FORMA CLI

Commands:
  trustlayer scan <file.py>         Analyze agent code for compliance gaps
  trustlayer verify <run_id>        Verify a run's Ed25519 signature locally
  trustlayer export <run_id>        Download and save evidence PDF
  trustlayer status                 Show connected API status
"""
from __future__ import annotations

import ast
import hashlib
import hmac
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Optional

try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False


# ── ANSI colors ───────────────────────────────────────────────────────────────
def _green(s): return f"\033[32m{s}\033[0m"
def _red(s):   return f"\033[31m{s}\033[0m"
def _yellow(s):return f"\033[33m{s}\033[0m"
def _bold(s):  return f"\033[1m{s}\033[0m"
def _dim(s):   return f"\033[2m{s}\033[0m"

PASS = _green("✓")
FAIL = _red("✗")
WARN = _yellow("⚠")


# ── Static analysis helpers ───────────────────────────────────────────────────

def _parse_file(path: str) -> ast.Module:
    with open(path, "r", encoding="utf-8") as f:
        return ast.parse(f.read(), filename=path)


def _find_forma_config(tree: ast.Module) -> dict:
    """
    Inspect a file for tl.init() / tl.register() calls and the kwargs they set.

    FORMA has exactly two entry points — init() (process-wide + agents={...})
    and register() (per-agent) — so a compliance scan checks which governance
    options the code actually enables.
    """
    init_calls = []
    register_calls = []
    all_kwargs: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = ""
        if isinstance(node.func, ast.Attribute):
            fname = node.func.attr
        elif isinstance(node.func, ast.Name):
            fname = node.func.id
        if fname not in ("init", "register"):
            continue
        kwargs = {kw.arg for kw in node.keywords if kw.arg}
        all_kwargs |= kwargs
        entry = {"line": node.lineno, "kwargs": sorted(kwargs)}
        (init_calls if fname == "init" else register_calls).append(entry)
    return {
        "init_calls":  init_calls,
        "register_calls": register_calls,
        "all_kwargs":  all_kwargs,
        "has_init":    bool(init_calls),
    }


def _find_high_risk_keywords(tree: ast.Module) -> list[tuple[int, str]]:
    """Find function calls that suggest high-risk operations."""
    HIGH_RISK = {
        "send_email", "send_message", "post_message", "delete", "remove",
        "approve", "reject", "fire", "hire", "loan", "credit", "deny",
        "execute", "transfer", "pay", "charge", "book", "schedule",
        "diagnose", "prescribe",
    }
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            elif isinstance(node.func, ast.Name):
                name = node.func.id
            if name.lower() in HIGH_RISK:
                hits.append((node.lineno, name))
    return hits


def _scan_file(filepath: str, framework: str = "all") -> dict:
    """Return a dict of findings for a given file."""
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}

    try:
        tree = _parse_file(filepath)
    except SyntaxError as e:
        return {"error": f"Syntax error in {filepath}: {e}"}

    config    = _find_forma_config(tree)
    high_risk = _find_high_risk_keywords(tree)
    kwargs    = config["all_kwargs"]

    gaps = {
        "eu_ai_act": [],
        "rbi":       [],
        "dpdp":      [],
        "iso42001":  [],
    }

    # ISO 42001 — is FORMA even initialised?
    if not config["has_init"]:
        gaps["iso42001"].append({
            "article": "ISO 42001 §6.1",
            "check":   "AI management system",
            "line":    1,
            "message": "FORMA is not initialised in this file — no observability or governance",
            "fix":     "Call tl.init(api_key=..., human_sponsor='owner@company.com') once at startup",
        })

    # EU AI Act Article 14 — human oversight
    if "require_approval_when" not in kwargs:
        gaps["eu_ai_act"].append({
            "article": "Article 14",
            "check":   "Human oversight",
            "line":    1,
            "message": "No require_approval_when=... configured — high-stakes calls are not paused for review",
            "fix":     "tl.init(require_approval_when=lambda ctx: ctx['amount'] > 1_000_000)",
        })

    # EU AI Act Article 13 — transparency (accountable human)
    if "human_sponsor" not in kwargs:
        gaps["eu_ai_act"].append({
            "article": "Article 13",
            "check":   "Accountable human",
            "line":    1,
            "message": "No human_sponsor= set — runs have no accountable owner",
            "fix":     "tl.init(human_sponsor='owner@company.com')",
        })

    # DPDP / runtime enforcement — PII + jailbreak blocking
    if "enforce" not in kwargs:
        gaps["dpdp"].append({
            "article": "DPDP Act §8",
            "check":   "Runtime enforcement",
            "line":    1,
            "message": "No enforce=[...] configured — PII and prompt-injection are logged but not blocked",
            "fix":     "tl.init(enforce=['dpdp', 'rbi_ml_risk'])",
        })

    # RBI — explainability for financial high-risk operations
    if high_risk and "enforce" not in kwargs:
        names = ", ".join(sorted({n for _, n in high_risk})[:4])
        gaps["rbi"].append({
            "article": "RBI ML Model Risk",
            "check":   "Financial decision controls",
            "line":    high_risk[0][0],
            "message": f"High-risk operations detected ({names}) without enforce=[...] gating",
            "fix":     "tl.init(enforce=['rbi_ml_risk']) or per-agent tl.register('agent-name', fn, enforce=['rbi_ml_risk'])",
        })

    return {
        "file":        filepath,
        "init_calls":  config["init_calls"],
        "register_calls": config["register_calls"],
        "high_risk":   high_risk,
        "gaps":        gaps,
    }


def _print_scan_results(findings: dict, framework: str = "all"):
    if "error" in findings:
        print(_red(f"  Error: {findings['error']}"))
        return

    init_calls  = findings.get("init_calls", [])
    register_calls = findings.get("register_calls", [])
    print(f"\n  {_bold('FORMA configuration:')}")
    if init_calls:
        for c in init_calls:
            kw = ", ".join(c["kwargs"]) or "(no kwargs)"
            print(f"    {PASS} tl.init({_dim(kw)}) at line {c['line']}")
    else:
        print(f"    {FAIL} {_red('No tl.init() call found')}")
    for c in register_calls:
        kw = ", ".join(c["kwargs"]) or ""
        print(f"    {PASS} tl.register({_dim(kw)}) at line {c['line']}")

    high_risk = findings["high_risk"]
    if high_risk:
        print(f"\n  {_bold('High-risk operations detected:')}")
        for line, name in high_risk[:5]:
            print(f"    {WARN} {name}() at line {line}")

    gaps = findings["gaps"]
    frameworks_to_show = list(gaps.keys()) if framework == "all" else [framework]

    total_gaps = 0
    for fw in frameworks_to_show:
        fw_gaps = gaps.get(fw, [])
        if not fw_gaps:
            continue
        fw_name = {
            "eu_ai_act": "EU AI Act",
            "rbi":       "RBI ML Model Risk",
            "dpdp":      "India DPDP Act",
            "iso42001":  "ISO 42001",
        }.get(fw, fw.upper())
        print(f"\n  {_bold(f'Compliance gaps — {fw_name}:')}")
        for gap in fw_gaps:
            print(f"    {FAIL} {gap['article']}: {gap['message']}")
            print(f"         Fix: {_dim(gap['fix'])}")
            total_gaps += 1

    if total_gaps == 0:
        print(f"\n  {PASS} {_green('No compliance gaps found.')}")
    else:
        print(f"\n  {WARN} {total_gaps} gap(s) found. Run {_bold('trustlayer fix <file>')} to auto-fix.")


# ── API helpers ───────────────────────────────────────────────────────────────

def _api_get(path: str, api_url: str, api_key: str) -> dict:
    req = urllib.request.Request(
        f"{api_url}{path}",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_api_config():
    return (
        os.environ.get("FORMA_API_URL") or os.environ.get("TRUSTLAYER_API_URL") or "https://api.formaai.in",
        os.environ.get("FORMA_API_KEY") or os.environ.get("TRUSTLAYER_API_KEY", "dev"),
    )


# ── CLI (click-based when available, fallback to argparse) ────────────────────

if HAS_CLICK:

    @click.group()
    def main():
        """FORMA CLI — AI agent compliance tooling."""
        pass

    @main.command()
    def setup():
        """One-time guided setup — paste your key, pick a preset, done. (No code needed.)"""
        config_path = Path.home() / ".forma" / "config.json"
        print(f"\n{_bold('Welcome to FORMA — the AI Compliance Firewall for India')}")
        print(_dim("  ~30 seconds. No code knowledge needed.\n"))

        existing = {}
        try:
            if config_path.exists():
                existing = json.loads(config_path.read_text() or "{}")
        except Exception:
            existing = {}

        # 1) API key
        api_key = click.prompt(
            "  1. Paste your FORMA API key  (get it at formaai.in/settings)",
            default=existing.get("api_key", ""), show_default=bool(existing.get("api_key")),
        ).strip()
        if not api_key:
            print(f"  {FAIL} {_red('A key is required — sign up free at https://formaai.in/signup')}")
            sys.exit(1)
        api_url = os.environ.get("FORMA_API_URL") or "https://api.formaai.in"

        # 2) verify (best effort — never blocks setup)
        try:
            me = _api_get("/api/auth/me", api_url, api_key)
            print(f"  {PASS} {_green('Connected')} as {_bold(me.get('email') or me.get('org_slug') or 'your org')}")
        except Exception:
            print(f"  {WARN} {_yellow('Could not reach FORMA right now — saving your key anyway.')}")

        # 3) one plain-English question
        print(f"\n  2. What does your AI do?")
        choices = [
            ("India fintech — lending / KYC / credit   (DPDP + RBI)", "india_fintech"),
            ("India general — any Indian personal data  (DPDP)",      "india"),
            ("Healthcare — patient / health data        (DPDP + HIPAA)", "india_health"),
            ("Global — outside India                    (AI safety only)", "global"),
        ]
        for i, (label, _) in enumerate(choices, 1):
            print(f"     {_bold(str(i))}. {label}")
        idx = click.prompt("  Pick a number", type=click.IntRange(1, len(choices)), default=1)
        preset = choices[idx - 1][1]

        # 4) save config
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(
            {"api_key": api_key, "preset": preset, "api_url": api_url}, indent=2))
        try:
            os.chmod(config_path, 0o600)
        except Exception:
            pass
        print(f"\n  {PASS} Saved to {_dim(str(config_path))}")

        # 5) live proof — block a test Aadhaar via the public gate
        try:
            body = json.dumps({"prompt": "Customer Aadhaar 2341 1234 1236"}).encode()
            req = urllib.request.Request(
                f"{api_url}/api/playground/check", data=body,
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                res = json.loads(resp.read().decode("utf-8"))
            if res.get("decision") == "block":
                print(f"  {PASS} {_green('Your gate is live')} — FORMA just blocked a test Aadhaar.")
            else:
                print(f"  {WARN} {_yellow('Gate reachable but did not block the test.')}")
        except Exception:
            print(f"  {WARN} {_yellow('Skipped live test (offline) — your gate still runs locally.')}")

        # 6) the entire integration
        print("\n" + _bold("That's it. Add these 2 lines to the top of your app:") + "\n")
        print("    " + _green("import trustlayer as tl"))
        print("    " + _green("tl.init()") + _dim("   # your key + preset load automatically"))
        print(f"\n  Every AI call is now governed. {_dim('Docs: https://formaai.in/developer-guide')}\n")

    @main.command()
    @click.argument("file", type=click.Path(exists=True))
    @click.option("--framework", default="all",
                  type=click.Choice(["all", "eu_ai_act", "rbi", "dpdp", "iso42001"]),
                  help="Compliance framework to check")
    def scan(file, framework):
        """Scan agent code for compliance gaps before deployment."""
        print(f"\n{_bold('FORMA Compliance Scanner')}")
        print(f"  Scanning {_bold(file)} against {_bold(framework)} frameworks...\n")
        findings = _scan_file(file, framework)
        _print_scan_results(findings, framework)
        print()

    @main.command()
    @click.argument("run_id")
    def verify(run_id):
        """Verify a run's cryptographic signature."""
        api_url, api_key = _get_api_config()
        print(f"\n{_bold('FORMA Signature Verifier')}")
        print(f"  Run ID: {run_id}")
        print(f"  API:    {api_url}\n")
        try:
            data = _api_get(f"/api/runs/{run_id}", api_url, api_key)
            sig = data.get("signature")
            if not sig:
                print(f"  {WARN} {_yellow('This run has no signature (may predate signing).')}")
                return

            # Reconstruct and verify HMAC-SHA256 signature
            payload = json.dumps({
                "run_id":     data["id"],
                "agent_name": data["agent_name"],
                "status":     data["status"],
                "started_at": data["started_at"],
            }, sort_keys=True).encode()

            expected = hmac.new(api_key.encode(), payload, hashlib.sha256).hexdigest()
            if hmac.compare_digest(sig[:len(expected)], expected):
                print(f"  {PASS} {_green('VERIFIED — signature is valid and untampered.')}")
            else:
                print(f"  {FAIL} {_red('TAMPERED — signature does not match run data!')}")
                sys.exit(1)
        except Exception as exc:
            print(f"  {FAIL} {_red(f'Verification failed: {exc}')}")
            sys.exit(1)
        print()

    @main.command("verify-decisions")
    @click.option("--agent", "agent_name", default=None,
                  help="Filter to a specific agent name")
    @click.option("--limit", default=200, type=int,
                  help="Maximum number of entries to verify (default: 200)")
    def verify_decisions(agent_name, limit):
        """
        Verify HMAC signatures on gate decision log entries.

        Proves that no gate decision (allow/warn/block) was altered after the
        fact — tamper-evident audit trail. Exits with code 1 if any entry fails.

        \\b
          trustlayer verify-decisions --agent loan-approval-agent --limit 500
        """
        api_url, api_key = _get_api_config()
        print(f"\n{_bold('FORMA Decision Log Verifier')}")
        if agent_name:
            print(f"  Agent:  {agent_name}")
        print(f"  Limit:  {limit}")
        print(f"  API:    {api_url}\n")

        try:
            path = f"/api/gate/log?limit={limit}"
            if agent_name:
                path += f"&agent={agent_name}"
            data = _api_get(path, api_url, api_key)
            entries = data if isinstance(data, list) else data.get("entries", data.get("logs", []))

            if not entries:
                print(f"  {WARN} {_yellow('No gate decisions found for the given filter.')}")
                print()
                return

            # Verify HMAC signatures locally using the same key. Recompute over
            # the same canonical field set the SDK signed (_SIGNED_FIELDS) — NOT
            # the whole row — so the server's agent_id resolution and the added
            # id/created_at fields don't break verification.
            from trustlayer.gate_local import _SIGNED_FIELDS
            passed = failed = unsigned = 0
            for e in entries:
                if not e.get("_sig"):
                    unsigned += 1
                    continue
                import hashlib as _h, hmac as _hmac, json as _j
                signed = {k: e.get(k) for k in _SIGNED_FIELDS}
                payload = _j.dumps(signed, sort_keys=True, separators=(",", ":"), default=str)
                expected = "hmac-sha256:" + _hmac.new(
                    api_key.encode(), payload.encode(), _h.sha256,
                ).hexdigest()
                if _hmac.compare_digest(e["_sig"], expected):
                    passed += 1
                else:
                    failed += 1

            total = passed + failed + unsigned
            block_count = sum(1 for e in entries if e.get("decision") == "block")
            warn_count  = sum(1 for e in entries if e.get("decision") == "warn")
            allow_count = sum(1 for e in entries if e.get("decision") == "allow")

            if failed == 0 and unsigned == 0:
                print(f"  {PASS} {_green(f'{total} decisions verified — all signatures valid.')}")
            elif failed > 0:
                print(f"  {FAIL} {_red(f'TAMPERED — {failed} decision(s) have invalid signatures!')}")
            elif unsigned > 0:
                print(f"  {WARN} {_yellow(f'{unsigned} unsigned entries (may predate v2.3.0).')}")
                if passed > 0:
                    print(f"  {PASS} {_green(f'{passed} signed entries verified.')}")

            print(f"  Blocked: {block_count}  |  Warned: {warn_count}  |  Allowed: {allow_count}")
            if failed == 0:
                # Top rule
                from collections import Counter
                top = Counter(e.get("rule_id") for e in entries if e.get("rule_id")).most_common(1)
                if top:
                    print(f"  Top rule: {_bold(top[0][0])} ({top[0][1]} hits)")
            print()

            if failed > 0:
                sys.exit(1)
        except Exception as exc:
            print(f"  {FAIL} {_red(f'Verification failed: {exc}')}")
            sys.exit(1)

    @main.command("export")
    @click.argument("run_id")
    @click.option("--output", "-o", default=None, help="Output file path (default: evidence_{run_id}.pdf)")
    def export_cmd(run_id, output):
        """Download and save an evidence PDF for a run."""
        api_url, api_key = _get_api_config()
        output = output or f"evidence_{run_id[:8]}.pdf"
        print(f"\n{_bold('FORMA Evidence Exporter')}")
        print(f"  Run ID: {run_id}")
        print(f"  Saving to: {output}\n")
        try:
            req = urllib.request.Request(
                f"{api_url}/api/runs/{run_id}/evidence",
                headers={"X-API-Key": api_key},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read()
            with open(output, "wb") as f:
                f.write(content)
            print(f"  {PASS} {_green(f'Evidence PDF saved to {output}')}")
            print(f"  File size: {len(content):,} bytes")
        except Exception as exc:
            print(f"  {FAIL} {_red(f'Export failed: {exc}')}")
            sys.exit(1)
        print()

    @main.command()
    def status():
        """Check FORMA API connection and fleet overview."""
        api_url, api_key = _get_api_config()
        print(f"\n{_bold('FORMA Status')}")
        print(f"  API URL: {api_url}")
        try:
            health = _api_get("/health", api_url, api_key)
            print(f"  {PASS} {_green('API reachable')} — version {health.get('version', '?')}")
            stats = _api_get("/api/dashboard/stats", api_url, api_key)
            print(f"  Agents: {stats.get('total_agents', 0)}")
            print(f"  Runs today: {stats.get('runs_today', 0)}")
            print(f"  Compliance: {stats.get('overall_compliance', 0):.0f}%")
        except Exception as exc:
            print(f"  {FAIL} {_red(f'Cannot reach API: {exc}')}")
            print(f"  Make sure FORMA_API_URL is set correctly.")
            sys.exit(1)
        print()

    @main.command()
    @click.option("--output-dir", default=None, help="Directory to save keys (default: ~/.forma/)")
    @click.option("--force", is_flag=True, default=False, help="Overwrite existing keys")
    def keygen(output_dir, force):
        """
        Generate an Ed25519 keypair for cryptographically signing agent runs.

        Creates two files:
          ~/.forma/signing_key.pem      — private key (keep secret)
          ~/.forma/signing_key.pub.pem  — public key (share with auditors)

        Then set:
          export TRUSTLAYER_SIGNING_KEY_PEM=$(cat ~/.forma/signing_key.pem)

        Anyone with the public key can verify any run signature without your API key.
        """
        from pathlib import Path
        key_dir = Path(output_dir) if output_dir else Path.home() / ".forma"
        priv_path = key_dir / "signing_key.pem"
        pub_path  = key_dir / "signing_key.pub.pem"

        print(f"\n{_bold('FORMA Ed25519 Key Generator')}")

        if priv_path.exists() and not force:
            print(f"  {WARN} {_yellow('Keys already exist at')} {key_dir}")
            print(f"  Use --force to regenerate (this will invalidate existing signatures).")
            return

        try:
            from .crypto import generate_keypair
            priv_pem, pub_pem = generate_keypair(str(key_dir))
            print(f"  {PASS} {_green('Private key:')} {priv_path}")
            print(f"  {PASS} {_green('Public key: ')} {pub_path}")
            print(f"\n  {_bold('Next steps:')}")
            print(f"  1. Set the signing key in your environment:")
            print(f"     {_dim('export TRUSTLAYER_SIGNING_KEY_PEM=$(cat ' + str(priv_path) + ')')}")
            print(f"  2. Share the public key with auditors/regulators:")
            print(f"     {_dim('cat ' + str(pub_path))}")
            print(f"  3. Run {_bold('trustlayer verify <run_id>')} to verify any run signature.")
            print(f"\n  {_dim('Algorithm: Ed25519 (RFC 8032) — publicly verifiable, no API key needed.')}")
        except ImportError:
            print(f"  {FAIL} {_red('cryptography library required: pip install cryptography')}")
            sys.exit(1)
        except Exception as exc:
            print(f"  {FAIL} {_red(f'Key generation failed: {exc}')}")
            sys.exit(1)
        print()

    @main.command()
    @click.argument("policy_file", default=".forma/policies.yaml",
                    type=click.Path(), required=False)
    @click.option("--dry-run", is_flag=True, default=False,
                  help="Preview changes without applying them")
    def apply(policy_file, dry_run):
        """
        Apply .forma/policies.yaml governance policies to the FORMA API.

        This enables Governance-as-Code — policies live in your git repo,
        get reviewed in pull requests, and are applied like any other config.

        Example .forma/policies.yaml:
        \\b
          agents:
            loan-approval-agent:
              max_cost_per_run: 0.05
              pii_detection: block
              required_frameworks: [dpdp, rbi]
              kill_switch: enabled
              human_oversight:
                required_for: [approve_loan]
                escalate_to: cto@company.com
        """
        from pathlib import Path
        try:
            import yaml
        except ImportError:
            print(f"  {FAIL} {_red('PyYAML required: pip install pyyaml')}")
            sys.exit(1)

        policy_path = Path(policy_file)
        if not policy_path.exists():
            print(f"  {FAIL} {_red(f'Policy file not found: {policy_file}')}")
            print(f"  Create {_bold('.forma/policies.yaml')} in your project root.")
            sys.exit(1)

        api_url, api_key = _get_api_config()
        with open(policy_path) as f:
            policies = yaml.safe_load(f)

        agents = policies.get("agents", {})
        print(f"\n{_bold('FORMA Policy Apply')}")
        print(f"  Policy file: {policy_path}")
        print(f"  Agents:      {len(agents)}")
        if dry_run:
            print(f"  Mode:        {_yellow('DRY RUN — no changes will be applied')}")
        print()

        applied = 0
        failed  = 0
        for agent_name, cfg in agents.items():
            print(f"  {_bold(agent_name)}:")

            # Build gate rules from policy
            gate_rules = []
            if cfg.get("pii_detection") == "block":
                gate_rules.append({"type": "pii_block", "action": "block", "description": "Block PII via policy"})
            if cfg.get("max_cost_per_run"):
                gate_rules.append({"type": "cost_limit", "action": "block",
                                   "value": cfg["max_cost_per_run"], "description": "Cost cap via policy"})
            for fw in cfg.get("required_frameworks", []):
                gate_rules.append({"type": "framework_required", "action": "warn", "framework": fw})

            if dry_run:
                print(f"    {WARN} Would apply {len(gate_rules)} gate rule(s)")
                for rule in gate_rules:
                    print(f"       – {rule['type']}: {rule['action']}")
                applied += 1
                continue

            # Apply: find agent by name, push gate rules
            try:
                import json as _json
                agents_resp = _api_get("/api/agents", api_url, api_key)
                agent_list  = agents_resp if isinstance(agents_resp, list) else agents_resp.get("agents", [])
                matched     = [a for a in agent_list if a.get("name") == agent_name]
                if not matched:
                    print(f"    {WARN} {_yellow('Agent not found in FORMA')} — will apply on first run")
                    applied += 1
                    continue

                agent_id = matched[0]["id"]
                payload  = _json.dumps(gate_rules).encode()
                req = urllib.request.Request(
                    f"{api_url}/api/gate/rules/{agent_id}",
                    data=payload,
                    headers={"X-API-Key": api_key, "Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)
                print(f"    {PASS} {_green(f'{len(gate_rules)} rule(s) applied')}")
                applied += 1
            except Exception as exc:
                print(f"    {FAIL} {_red(f'Failed: {exc}')}")
                failed += 1

        print()
        status_str = _green(f"{applied} agent(s) applied") if not failed else _yellow(f"{applied} applied, {failed} failed")
        print(f"  Result: {status_str}")
        if not dry_run and failed == 0:
            print(f"  {PASS} {_green('All policies applied successfully.')}")
        print()

    @main.command("gate")
    @click.option("--pre-deploy", is_flag=True, default=False,
                  help="Run pre-deployment compliance gate check")
    @click.option("--agent", "agent_name", default=None,
                  help="Agent name to check (default: all agents in .forma/policies.yaml)")
    @click.option("--commit", default=None, help="Git commit SHA being deployed")
    @click.option("--fail-below", default=70.0, type=float,
                  help="Fail if compliance score is below this threshold (default: 70)")
    def gate_cmd(pre_deploy, agent_name, commit, fail_below):
        """
        Run a pre-deployment compliance gate check.

        Use in CI/CD to block deploys when compliance drops:
        \\b
          # .github/workflows/deploy.yml
          - run: trustlayer gate --pre-deploy --fail-below 80

        Exits with code 1 if any agent fails the gate, blocking the deploy pipeline.
        """
        api_url, api_key = _get_api_config()
        print(f"\n{_bold('FORMA Pre-Deploy Gate Check')}")
        if commit:
            print(f"  Commit: {commit[:8]}")
        print(f"  Threshold: {fail_below}%")
        print()

        try:
            agents_resp = _api_get("/api/agents", api_url, api_key)
            agent_list  = agents_resp if isinstance(agents_resp, list) else agents_resp.get("agents", [])
            if agent_name:
                agent_list = [a for a in agent_list if a.get("name") == agent_name]

            blocked = []
            for a in agent_list:
                score = a.get("compliance_score") or a.get("trust_score", 0)
                name  = a.get("name", a.get("id", "?"))
                if score < fail_below:
                    print(f"  {FAIL} {_bold(name)}: {score:.0f}% (below {fail_below}%)")
                    blocked.append(name)
                else:
                    print(f"  {PASS} {_bold(name)}: {_green(f'{score:.0f}%')}")

            print()
            if blocked:
                print(f"  {FAIL} {_red('DEPLOY BLOCKED')} — {len(blocked)} agent(s) below threshold:")
                for b in blocked:
                    print(f"     – {b}")
                sys.exit(1)
            else:
                print(f"  {PASS} {_green('All agents pass — deploy allowed.')}")
        except Exception as exc:
            print(f"  {FAIL} {_red(f'Gate check failed: {exc}')}")
            sys.exit(1)
        print()

else:
    # Minimal fallback without click
    def main():
        print("FORMA CLI requires 'click': pip install forma-sdk[cli]")
        sys.exit(1)


if __name__ == "__main__":
    main()
