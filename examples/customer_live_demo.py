"""
PROVN — Live Customer Demo
================================
Simulates a real fintech/HR company using PROVN to govern 3 AI agents:

  1. CV Screening Agent      — HIGH risk, authorized actions enforced
  2. Loan Approval Agent     — CRITICAL risk, kill-switch enabled
  3. Customer Support Agent  — MEDIUM risk, low-cost helper

Runs 15 times across agents to generate:
  - Dashboard metrics (runs, tokens, cost, latency)
  - Behavioral fingerprint data
  - Anomaly detection events
  - Multi-agent chain (CV → Loan pipeline)
  - Compliance certificate issuance
  - Shadow agent events

Usage:
  python customer_live_demo.py
"""

import json
import random
import time
import urllib.request
import uuid
from datetime import datetime, timezone

API_KEY = "tl_live_7a9851c5dcb6e2036aba5df9c5bf266c0434c7a7"
API_URL = "http://127.0.0.1:8001"

# ── helpers ──────────────────────────────────────────────────────────────────

def post(path, payload, method="POST"):
    data = json.dumps(payload, default=str).encode()
    req = urllib.request.Request(
        url=f"{API_URL}{path}",
        data=data,
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  [warn] {path} failed: {e}")
        return {}

def get(path):
    req = urllib.request.Request(
        url=f"{API_URL}{path}",
        headers={"X-API-Key": API_KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  [warn] GET {path} failed: {e}")
        return {}

def make_run(agent_name, agent_version, sponsor, status, tokens, cost, duration_ms,
             steps, error=None, chain_id=None, parent_run_id=None, chain_depth=0):
    now = datetime.now(timezone.utc)
    run_id = str(uuid.uuid4())
    meta = {}
    if chain_id:
        meta = {
            "chain_id": chain_id,
            "parent_run_id": parent_run_id,
            "chain_depth": chain_depth,
            "input_hash": str(uuid.uuid4())[:16],
            "output_hash": str(uuid.uuid4())[:16],
        }
    return post("/api/runs", {
        "run_id": run_id,
        "agent_name": agent_name,
        "agent_version": agent_version,
        "human_sponsor": sponsor,
        "started_at": now.isoformat(),
        "ended_at": now.isoformat(),
        "duration_ms": duration_ms,
        "status": status,
        "steps": steps,
        "total_tokens": tokens,
        "total_cost_usd": cost,
        "error": error,
        "signature": f"hmac-sha256:{uuid.uuid4().hex}",
        "metadata": meta,
    }), run_id

def llm_step(label, model, prompt_tokens, completion_tokens, cost_usd, duration_ms):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "step_number": 1,
        "step_type": "llm",
        "label": label,
        "started_at": now,
        "ended_at": now,
        "duration_ms": duration_ms,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cost_usd": cost_usd,
        "status": "success",
    }

def tool_step(label, tool_name, duration_ms):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "step_number": 2,
        "step_type": "tool",
        "label": label,
        "started_at": now,
        "ended_at": now,
        "duration_ms": duration_ms,
        "tool_name": tool_name,
        "tool_args": {"query": "customer_data"},
        "status": "success",
    }

def banner(text):
    print(f"\n{'═'*60}")
    print(f"  {text}")
    print(f"{'═'*60}")

# ── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    banner("PROVN — Live Customer Demo")
    print(f"  API Key : {API_KEY[:20]}…")
    print(f"  API URL : {API_URL}")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Step 1: Register agent passports ────────────────────────────────────
    banner("Step 1 — Registering Agent Identity Passports")

    agents_to_register = [
        {
            "name": "cv-screening-agent",
            "purpose": "Screens candidate CVs for HR team — reads CV data and scores against job criteria",
            "authorized_actions": ["read_cv", "score_candidate", "send_result_email"],
            "risk_level": "HIGH",
            "human_sponsor": "cto@talentcorp.in",
            "kill_switch_enabled": True,
            "compliance_frameworks": ["DPDP", "EU_AI_ACT"],
        },
        {
            "name": "loan-approval-agent",
            "purpose": "Evaluates personal loan applications for amounts up to ₹10 lakhs",
            "authorized_actions": ["read_credit_score", "check_bank_statement", "approve_loan", "reject_loan"],
            "risk_level": "CRITICAL",
            "human_sponsor": "riskteam@finbank.in",
            "kill_switch_enabled": True,
            "compliance_frameworks": ["DPDP", "RBI", "EU_AI_ACT"],
        },
        {
            "name": "customer-support-agent",
            "purpose": "Handles tier-1 customer support queries for SaaS product",
            "authorized_actions": ["read_ticket", "respond_ticket", "escalate_ticket"],
            "risk_level": "MEDIUM",
            "human_sponsor": "support-lead@saasco.in",
            "kill_switch_enabled": False,
            "compliance_frameworks": ["DPDP"],
        },
    ]

    agent_ids = {}

    for ag in agents_to_register:
        # First do a run to create the agent
        run_result, _ = make_run(
            agent_name=ag["name"],
            agent_version="1.0.0",
            sponsor=ag["human_sponsor"],
            status="success",
            tokens=500,
            cost=0.001,
            duration_ms=900,
            steps=[llm_step("warmup", "gpt-4o-mini", 400, 100, 0.001, 900)],
        )
        agent_id = run_result.get("agent_id")
        if not agent_id:
            print(f"  ✗ Could not create agent: {ag['name']}")
            continue

        agent_ids[ag["name"]] = agent_id

        # Issue passport
        passport = post(f"/api/passport/{agent_id}", {
            "purpose": ag["purpose"],
            "authorized_actions": ag["authorized_actions"],
            "risk_level": ag["risk_level"],
            "human_sponsor": ag["human_sponsor"],
            "kill_switch_enabled": ag["kill_switch_enabled"],
            "compliance_frameworks": ag["compliance_frameworks"],
            "expires_days": 90,
            "drift_threshold": 0.15,
        })
        print(f"  ✅ {ag['name']}")
        print(f"     Passport: {passport.get('id', 'N/A')} | Risk: {passport.get('risk_level')} | Expires: {passport.get('expires_at', 'N/A')[:10] if passport.get('expires_at') else 'never'}")

    time.sleep(0.5)

    # ── Step 2: Run CV Screening Agent 8 times ─────────────────────────────
    banner("Step 2 — Running CV Screening Agent (8 candidate CVs)")

    cv_agent_id = agent_ids.get("cv-screening-agent")
    cv_run_ids = []

    cv_scenarios = [
        (1850, 3200, 1980, 0.0312, "success", "GPT-4o scored Rajesh Kumar: 87/100 — SHORTLISTED"),
        (2100, 3400, 2100, 0.0351, "success", "GPT-4o scored Priya Singh: 72/100 — SHORTLISTED"),
        (1650, 2900, 1750, 0.0278, "success", "GPT-4o scored Amit Sharma: 58/100 — REJECTED"),
        (1920, 3150, 1890, 0.0321, "success", "GPT-4o scored Deepika Nair: 91/100 — SHORTLISTED"),
        (8900, 9200, 5800, 0.1420, "success", "Anomaly: Extra-large CV batch — 6 candidates processed"),  # spike
        (1780, 3050, 1920, 0.0299, "success", "GPT-4o scored Vikram Mehta: 65/100 — SHORTLISTED"),
        (1900, 3200, 2050, 0.0318, "failed", "Tool error: Database timeout when fetching job criteria"),
        (1850, 3100, 1970, 0.0308, "success", "GPT-4o scored Ananya Patel: 79/100 — SHORTLISTED"),
    ]

    for i, (prompt_tok, total_tok, duration, cost, status, label) in enumerate(cv_scenarios):
        comp_tok = total_tok - prompt_tok
        steps = [
            llm_step(label, "gpt-4o", prompt_tok, comp_tok, cost * 0.8, duration - 200),
            tool_step("Fetch job criteria from HR DB", "hr_database_query", 200),
        ]
        result, run_id = make_run(
            agent_name="cv-screening-agent",
            agent_version="1.0.0",
            sponsor="cto@talentcorp.in",
            status=status,
            tokens=total_tok,
            cost=cost,
            duration_ms=duration,
            steps=steps,
            error="Tool error: Database timeout when fetching job criteria" if status == "failed" else None,
        )
        cv_run_ids.append(run_id)
        icon = "✅" if status == "success" else "❌"
        anomaly_flag = " ⚠️ ANOMALY" if total_tok > 5000 else ""
        print(f"  {icon} Run {i+1}: {total_tok:,} tokens · ${cost:.4f} · {duration}ms{anomaly_flag}")
        time.sleep(0.2)

    # ── Step 3: Run Loan Approval Agent with chain ──────────────────────────
    banner("Step 3 — Loan Approval Pipeline (Multi-Agent Chain: CV → Loan)")

    loan_agent_id = agent_ids.get("loan-approval-agent")
    chain_id = str(uuid.uuid4())

    loan_scenarios = [
        (3200, 4800, 2800, 0.0621, "success",  "Loan ₹5L approved — CIBIL 780, income verified"),
        (4100, 5900, 3200, 0.0782, "success",  "Loan ₹8L approved — CIBIL 810, 3yr employment"),
        (2900, 4500, 2600, 0.0581, "success",  "Loan ₹3L approved — CIBIL 720, partial docs"),
        (3500, 5100, 2900, 0.0659, "failed",   "Loan REJECTED — CIBIL 590, income insufficient"),
        (3800, 5400, 3100, 0.0701, "success",  "Loan ₹10L approved — CIBIL 830, excellent history"),
    ]

    parent_run = cv_run_ids[0] if cv_run_ids else None
    for i, (prompt_tok, total_tok, duration, cost, status, label) in enumerate(loan_scenarios):
        comp_tok = total_tok - prompt_tok
        steps = [
            llm_step(label, "gpt-4o", prompt_tok, comp_tok, cost * 0.7, duration - 400),
            tool_step("Pull CIBIL credit score", "cibil_api", 200),
            tool_step("Verify income documents", "income_verification", 200),
        ]
        result, run_id = make_run(
            agent_name="loan-approval-agent",
            agent_version="2.1.0",
            sponsor="riskteam@finbank.in",
            status=status,
            tokens=total_tok,
            cost=cost,
            duration_ms=duration,
            steps=steps,
            error="RBI compliance: loan rejected — CIBIL below threshold (590 < 650)" if status == "failed" else None,
            chain_id=chain_id,
            parent_run_id=parent_run,
            chain_depth=i,
        )
        parent_run = run_id
        icon = "✅" if status == "success" else "❌"
        print(f"  {icon} Chain hop {i+1}: {label[:50]} · ${cost:.4f}")
        time.sleep(0.2)

    print(f"\n  Chain ID: {chain_id[:12]}… (verify at /chains/{chain_id})")

    # ── Step 4: Run Customer Support Agent ─────────────────────────────────
    banner("Step 4 — Customer Support Agent (8 support tickets)")

    support_agent_id = agent_ids.get("customer-support-agent")
    support_scenarios = [
        (420, 680, 850, 0.00205, "success", "Resolved billing query for user #4821"),
        (380, 610, 780, 0.00183, "success", "Answered API rate limit question"),
        (510, 790, 960, 0.00241, "success", "Guided user through integration setup"),
        (290, 510, 620, 0.00152, "success", "Escalated: Data export compliance question (DPDP)"),
        (450, 720, 880, 0.00218, "success", "Fixed OAuth redirect issue for user"),
        (390, 640, 810, 0.00192, "success", "Explained pricing tiers"),
        (620, 940, 1100, 0.00287, "failed",  "Failed: Slack webhook timeout on escalation"),
        (410, 670, 840, 0.00202, "success", "Resolved onboarding issue for new enterprise customer"),
    ]

    for i, (prompt_tok, total_tok, duration, cost, status, label) in enumerate(support_scenarios):
        comp_tok = total_tok - prompt_tok
        steps = [
            llm_step(label, "gpt-4o-mini", prompt_tok, comp_tok, cost, duration),
        ]
        make_run(
            agent_name="customer-support-agent",
            agent_version="1.2.0",
            sponsor="support-lead@saasco.in",
            status=status,
            tokens=total_tok,
            cost=cost,
            duration_ms=duration,
            steps=steps,
            error="Slack webhook timeout" if status == "failed" else None,
        )
        icon = "✅" if status == "success" else "❌"
        print(f"  {icon} Ticket {i+1}: {label[:55]}")
        time.sleep(0.15)

    # ── Step 5: Issue compliance certificates ──────────────────────────────
    banner("Step 5 — Issuing Compliance Certificates")

    cert_frameworks = [
        ("cv-screening-agent", "dpdp"),
        ("loan-approval-agent", "rbi"),
        ("loan-approval-agent", "eu_ai_act"),
    ]

    for agent_name, framework in cert_frameworks:
        agent_id = agent_ids.get(agent_name)
        if not agent_id:
            continue
        cert = post(f"/api/certificates/issue/{agent_id}", {"framework": framework})
        cert_id = cert.get("id", "N/A")
        score = cert.get("score", 0)
        # score is stored as 0-1 fraction; multiply by 100 for display
        score_pct = round(score * 100, 0) if score <= 1 else round(score, 0)
        print(f"  🏅 {agent_name} / {framework.upper()}")
        print(f"     Cert ID: {cert_id} | Score: {score_pct:.0f}% | QR Code: {'✅' if cert.get('qr_code') else '—'}")
        print(f"     Verify : {API_URL}/verify/{cert_id}")
        time.sleep(0.3)

    # ── Step 6: Simulate shadow agent detection ─────────────────────────────
    banner("Step 6 — Shadow Agent Events (untracked LLM calls)")

    shadow_events = [
        {"model": "gpt-4o", "provider": "openai", "caller_file": "analytics.py",
         "caller_func": "generate_report", "caller_module": "reports.analytics",
         "prompt_tokens": 2800, "completion_tokens": 900, "est_cost_usd": 0.0275},
        {"model": "gpt-4o", "provider": "openai", "caller_file": "analytics.py",
         "caller_func": "generate_report", "caller_module": "reports.analytics",
         "prompt_tokens": 3100, "completion_tokens": 1100, "est_cost_usd": 0.0321},
        {"model": "claude-3-5-sonnet", "provider": "anthropic", "caller_file": "email_gen.py",
         "caller_func": "draft_email", "caller_module": "comms.email_gen",
         "prompt_tokens": 1500, "completion_tokens": 600, "est_cost_usd": 0.0135},
        {"model": "gpt-4o-mini", "provider": "openai", "caller_file": "utils.py",
         "caller_func": "summarize_log", "caller_module": "core.utils",
         "prompt_tokens": 800, "completion_tokens": 200, "est_cost_usd": 0.0002},
        {"model": "gpt-4o", "provider": "openai", "caller_file": "analytics.py",
         "caller_func": "generate_report", "caller_module": "reports.analytics",
         "prompt_tokens": 2900, "completion_tokens": 950, "est_cost_usd": 0.0289},
    ]

    result = post("/api/shadow/events", {"events": shadow_events})
    shadows = get("/api/shadow")
    total_shadow_cost = sum(s.get("est_cost_usd", 0) for s in shadows)
    print(f"  👻 {result.get('accepted', 0)} shadow events ingested")
    print(f"  👻 {len(shadows)} unique untracked callers discovered")
    print(f"  👻 Total untracked cost: ${total_shadow_cost:.4f}")
    for s in shadows:
        print(f"     • {s.get('caller_func')} in {s.get('caller_file')} — {s.get('model')} — risk {s.get('risk_score'):.1f}")

    # ── Step 7: Trigger drift scan ──────────────────────────────────────────
    banner("Step 7 — Behavioral Drift Scan")

    for name, agent_id in agent_ids.items():
        result = post(f"/api/agents/{agent_id}/drift/scan", {})
        alerts = result.get("new_alerts", 0)
        print(f"  📈 {name}: {alerts} new drift alerts")
        drift = get(f"/api/agents/{agent_id}/drift")
        print(f"     Status: {drift.get('status', 'unknown')} | Active alerts: {drift.get('active_alerts', 0)}")

    # ── Step 8: Verify chain integrity ──────────────────────────────────────
    banner("Step 8 — Chain Audit Verification")

    chain_data = get(f"/api/chains/{chain_id}")
    verify = get(f"/api/chains/{chain_id}/verify")
    print(f"  🔗 Chain: {chain_id[:12]}…")
    print(f"  🔗 Hops: {chain_data.get('run_count', 0)} agents")
    print(f"  🔗 Agents: {' → '.join(chain_data.get('agent_sequence', []))}")
    print(f"  🔗 Integrity: {verify.get('integrity', 'unknown').upper()}")
    print(f"  🔗 Checks passed: {verify.get('checks_passed', 0)} / {chain_data.get('run_count', 0)}")

    # ── Final summary ───────────────────────────────────────────────────────
    banner("✅ Live Demo Complete — Dashboard Summary")

    stats = get("/api/dashboard/stats")
    certs = get("/api/certificates")
    shadows_final = get("/api/shadow")

    print(f"\n  📊 Dashboard Stats:")
    print(f"     Total Agents  : {stats.get('total_agents', 0)}")
    print(f"     Runs today    : {stats.get('runs_today', 0)}")
    print(f"     Anomalies     : {stats.get('anomalies_today', 0)}")
    print(f"     Cost today    : ${stats.get('cost_today_usd', 0):.4f}")
    print(f"     Compliance    : {stats.get('overall_compliance', 0):.0f}%")

    print(f"\n  🏅 Certificates issued: {len(certs)}")
    for c in certs:
        sc = c.get("score", 0)
        pct = sc * 100 if sc <= 1 else sc
        print(f"     {c.get('id')} — {c.get('framework').upper()} — {pct:.0f}%")

    print(f"\n  👻 Shadow agents: {len(shadows_final)}")

    print(f"\n  🌐 Open the dashboard: http://localhost:3000/dashboard")
    print(f"  🔗 Chain audit:        http://localhost:3000/chains/{chain_id}")
    print(f"  👻 Shadow agents:      http://localhost:3000/shadow")
    print(f"  🏅 Certificates:       http://localhost:3000/compliance/certificates")
    print(f"  📚 API docs:           http://127.0.0.1:8001/docs")
    print()
