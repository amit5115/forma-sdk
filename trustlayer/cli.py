"""
PROVN CLI

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


def _find_tracked_functions(tree: ast.Module) -> list[dict]:
    """Find all functions decorated with @track or @tracker.track."""
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = [ast.unparse(d) for d in node.decorator_list]
        is_tracked = any(
            "track" in d for d in decorators
        )
        has_approval = any(
            "require_approval" in d for d in decorators
        )
        has_sponsor = any(
            "sponsor=" in d for d in decorators
        )
        results.append({
            "name":        node.name,
            "line":        node.lineno,
            "is_tracked":  is_tracked,
            "has_approval": has_approval,
            "has_sponsor": has_sponsor,
            "decorators":  decorators,
        })
    return results


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

    tracked   = _find_tracked_functions(tree)
    high_risk = _find_high_risk_keywords(tree)

    gaps = {
        "eu_ai_act": [],
        "rbi":       [],
        "dpdp":      [],
        "iso42001":  [],
    }

    for fn in tracked:
        if not fn["is_tracked"]:
            continue
        fname = fn["name"]
        line  = fn["line"]

        # EU AI Act Article 14 — human oversight
        if not fn["has_approval"]:
            gaps["eu_ai_act"].append({
                "article": "Article 14",
                "check":   "Human oversight",
                "function": fname,
                "line":    line,
                "message": f"No @require_approval on {fname}() — add for high-stakes operations",
                "fix":     f"@tracker.require_approval(via='webhook', url='YOUR_WEBHOOK_URL')",
            })

        # EU AI Act Article 13 — transparency (human sponsor)
        if not fn["has_sponsor"]:
            gaps["eu_ai_act"].append({
                "article": "Article 13",
                "check":   "Human sponsor",
                "function": fname,
                "line":    line,
                "message": f"No sponsor= set on @track for {fname}()",
                "fix":     f"@tracker.track(sponsor='owner@company.com')",
            })

        # RBI — explainability for financial functions
        financial_keywords = {"loan", "credit", "payment", "transaction", "transfer", "invest"}
        if any(k in fname.lower() for k in financial_keywords):
            gaps["rbi"].append({
                "article": "RBI ML Model Risk",
                "check":   "Financial decision explainability",
                "function": fname,
                "line":    line,
                "message": f"{fname}() appears to make financial decisions — RBI requires explainability",
                "fix":     "Use tracker.llm_call() with descriptive labels for each decision step",
            })

        # DPDP — automated decision affecting individuals
        individual_keywords = {"user", "customer", "applicant", "person", "patient", "employee"}
        params = [a.arg for a in ast.walk(tree) if isinstance(a, ast.arg)]
        if any(k in p.lower() for p in params for k in individual_keywords):
            gaps["dpdp"].append({
                "article": "DPDP Act §13",
                "check":   "Automated decision transparency",
                "function": fname,
                "line":    line,
                "message": f"{fname}() may affect individuals — DPDP requires purpose disclosure",
                "fix":     "Add risk_class='high' and a detailed description to agent registration",
            })

        # ISO 42001 — AI management system
        gaps["iso42001"].append({
            "article": "ISO 42001 §6.1",
            "check":   "AI risk assessment",
            "function": fname,
            "line":    line,
            "message": f"Risk classification for {fname}() not verifiable from code alone",
            "fix":     "Register agent with risk_class set in PROVN dashboard",
        })

    return {
        "file":      filepath,
        "tracked":   tracked,
        "high_risk": high_risk,
        "gaps":      gaps,
    }


def _print_scan_results(findings: dict, framework: str = "all"):
    if "error" in findings:
        print(_red(f"  Error: {findings['error']}"))
        return

    tracked = [f for f in findings["tracked"] if f["is_tracked"]]
    print(f"\n  {_bold('Tracked functions found:')} {len(tracked)}")
    for fn in tracked:
        print(f"    {PASS} {_bold(fn['name'])}() at line {fn['line']}")
        for d in fn["decorators"]:
            print(f"         {_dim(d)}")

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
        os.environ.get("FORMA_API_URL") or os.environ.get("TRUSTLAYER_API_URL") or "https://forma.2bd.net",
        os.environ.get("FORMA_API_KEY") or os.environ.get("TRUSTLAYER_API_KEY", "dev"),
    )


# ── CLI (click-based when available, fallback to argparse) ────────────────────

if HAS_CLICK:

    @click.group()
    def main():
        """PROVN CLI — AI agent compliance tooling."""
        pass

    @main.command()
    @click.argument("file", type=click.Path(exists=True))
    @click.option("--framework", default="all",
                  type=click.Choice(["all", "eu_ai_act", "rbi", "dpdp", "iso42001"]),
                  help="Compliance framework to check")
    def scan(file, framework):
        """Scan agent code for compliance gaps before deployment."""
        print(f"\n{_bold('PROVN Compliance Scanner')}")
        print(f"  Scanning {_bold(file)} against {_bold(framework)} frameworks...\n")
        findings = _scan_file(file, framework)
        _print_scan_results(findings, framework)
        print()

    @main.command()
    @click.argument("run_id")
    def verify(run_id):
        """Verify a run's cryptographic signature."""
        api_url, api_key = _get_api_config()
        print(f"\n{_bold('PROVN Signature Verifier')}")
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

    @main.command("export")
    @click.argument("run_id")
    @click.option("--output", "-o", default=None, help="Output file path (default: evidence_{run_id}.pdf)")
    def export_cmd(run_id, output):
        """Download and save an evidence PDF for a run."""
        api_url, api_key = _get_api_config()
        output = output or f"evidence_{run_id[:8]}.pdf"
        print(f"\n{_bold('PROVN Evidence Exporter')}")
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
        """Check PROVN API connection and fleet overview."""
        api_url, api_key = _get_api_config()
        print(f"\n{_bold('PROVN Status')}")
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
            print(f"  Make sure TRUSTLAYER_API_URL is set correctly.")
            sys.exit(1)
        print()

    @main.command()
    @click.option("--output-dir", default=None, help="Directory to save keys (default: ~/.provn/)")
    @click.option("--force", is_flag=True, default=False, help="Overwrite existing keys")
    def keygen(output_dir, force):
        """
        Generate an Ed25519 keypair for cryptographically signing agent runs.

        Creates two files:
          ~/.provn/signing_key.pem      — private key (keep secret)
          ~/.provn/signing_key.pub.pem  — public key (share with auditors)

        Then set:
          export TRUSTLAYER_SIGNING_KEY_PEM=$(cat ~/.provn/signing_key.pem)

        Anyone with the public key can verify any run signature without your API key.
        """
        from pathlib import Path
        key_dir = Path(output_dir) if output_dir else Path.home() / ".provn"
        priv_path = key_dir / "signing_key.pem"
        pub_path  = key_dir / "signing_key.pub.pem"

        print(f"\n{_bold('PROVN Ed25519 Key Generator')}")

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
    @click.argument("policy_file", default=".provn/policies.yaml",
                    type=click.Path(), required=False)
    @click.option("--dry-run", is_flag=True, default=False,
                  help="Preview changes without applying them")
    def apply(policy_file, dry_run):
        """
        Apply .provn/policies.yaml governance policies to the PROVN API.

        This enables Governance-as-Code — policies live in your git repo,
        get reviewed in pull requests, and are applied like any other config.

        Example .provn/policies.yaml:
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
            print(f"  Create {_bold('.provn/policies.yaml')} in your project root.")
            sys.exit(1)

        api_url, api_key = _get_api_config()
        with open(policy_path) as f:
            policies = yaml.safe_load(f)

        agents = policies.get("agents", {})
        print(f"\n{_bold('PROVN Policy Apply')}")
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
                    print(f"    {WARN} {_yellow('Agent not found in PROVN')} — will apply on first run")
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
                  help="Agent name to check (default: all agents in .provn/policies.yaml)")
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
        print(f"\n{_bold('PROVN Pre-Deploy Gate Check')}")
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
        print("PROVN CLI requires 'click': pip install trustlayer-sdk[cli]")
        sys.exit(1)


if __name__ == "__main__":
    main()
