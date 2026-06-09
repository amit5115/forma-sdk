"""
PROVN — Real Customer Walkthrough
=======================================
Scenario: You are "FinSafeAI" — a fintech startup with 3 AI agents:

  Agent 1: loan_screener      → screens loan applications (HIGH risk)
  Agent 2: fraud_detector     → flags suspicious transactions (CRITICAL risk)
  Agent 3: support_bot        → handles customer queries (LOW risk)

This script walks through the COMPLETE customer journey:

  STEP 1  → Sign up & get API key (done in dashboard)
  STEP 2  → Install SDK & init (2 lines of code)
  STEP 3  → Register agent passports (give agents an identity)
  STEP 4  → Run agents (send real runs with traces)
  STEP 5  → Trigger kill switch (emergency stop fraud_detector)
  STEP 6  → Build a multi-agent chain (loan_screener → fraud_detector)
  STEP 7  → Issue compliance certificate (DPDP / RBI proof)
  STEP 8  → Discover shadow agents (find untracked LLM calls)
  STEP 9  → Scan for behavioral drift
  STEP 10 → View everything in the dashboard

Run:  python real_customer_walkthrough.py
"""

import json, random, time, uuid, urllib.request
from datetime import datetime, timezone

# ── YOUR API KEY (replace with yours from dashboard → Settings) ───────────────
API_KEY = "tl_live_7a9851c5dcb6e2036aba5df9c5bf266c0434c7a7"
API_URL = "http://127.0.0.1:8001"

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def section(title):
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}")

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def info(msg): print(f"  {DIM}→{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}⚠{RESET}  {msg}")

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def post(path, payload=None, method="POST"):
    data = json.dumps(payload or {}, default=str).encode()
    req = urllib.request.Request(
        url=f"{API_URL}{path}",
        data=data,
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  {RED}[{e.code}]{RESET} {path} → {body[:120]}")
        return {}
    except Exception as e:
        print(f"  {RED}[err]{RESET} {path} → {e}")
        return {}

def get(path):
    req = urllib.request.Request(
        url=f"{API_URL}{path}",
        headers={"X-API-Key": API_KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"  {RED}[err]{RESET} GET {path} → {e}")
        return {}

# ── STEP 1: Check you're authenticated ───────────────────────────────────────

section("STEP 1 — Authentication check")
info("Using API key: " + API_KEY[:18] + "..." + API_KEY[-4:])
me = get("/api/me")
if me.get("email"):
    ok(f"Logged in as: {me['email']}  |  Org: {me.get('org_id','?')[:8]}...")
else:
    warn("Could not verify — check your API key or run the API server.")

# ── STEP 2: Register your 3 agents ───────────────────────────────────────────

section("STEP 2 — Register agents (one-time setup)")
info("In your code this is just:  tl.init(api_key='...', agent_name='...')")

AGENTS = [
    {"name": "loan_screener",  "risk": "high",     "version": "2.1.0", "description": "Screens loan applications using GPT-4o"},
    {"name": "fraud_detector", "risk": "critical",  "version": "1.4.0", "description": "Real-time fraud detection on transactions"},
    {"name": "support_bot",    "risk": "low",       "version": "3.0.0", "description": "Customer support using GPT-4o-mini"},
]

agent_ids = {}
for agent in AGENTS:
    r = post("/api/agents", agent)
    aid = r.get("id")
    if aid:
        agent_ids[agent["name"]] = aid
        ok(f"Registered '{agent['name']}'  →  ID: {aid[:8]}...  risk={agent['risk']}")
    else:
        # agent may already exist — look it up
        all_agents = get("/api/agents").get("agents", [])
        for a in all_agents:
            if a.get("name") == agent["name"]:
                agent_ids[agent["name"]] = a["id"]
                ok(f"'{agent['name']}' already exists  →  ID: {a['id'][:8]}...")
                break

# ── STEP 3: Issue Agent Passports ────────────────────────────────────────────

section("STEP 3 — Agent Identity Passports (cryptographic ID card)")
info("Each agent gets a signed passport: what it can do, who owns it, when it expires.")

PASSPORTS = {
    "loan_screener": {
        "purpose": "Screen loan applications for creditworthiness under RBI guidelines",
        "authorized_actions": ["read_credit_score", "call_llm", "write_decision"],
        "risk_level": "high",
        "human_sponsor": "Priya Sharma (CTO)",
        "expiry_days": 90,
        "compliance_frameworks": ["RBI_ML_RISK", "DPDP_2023"],
    },
    "fraud_detector": {
        "purpose": "Flag suspicious transactions in real-time",
        "authorized_actions": ["read_transactions", "call_llm", "send_alert"],
        "risk_level": "critical",
        "human_sponsor": "Rahul Mehta (VP Risk)",
        "expiry_days": 30,
        "compliance_frameworks": ["RBI_ML_RISK", "DPDP_2023", "ISO_42001"],
    },
    "support_bot": {
        "purpose": "Answer customer queries about account, products",
        "authorized_actions": ["read_faqs", "call_llm", "send_message"],
        "risk_level": "low",
        "human_sponsor": "Aarav Kumar (Head of CX)",
        "expiry_days": 180,
        "compliance_frameworks": ["DPDP_2023"],
    },
}

for name, passport_data in PASSPORTS.items():
    aid = agent_ids.get(name)
    if not aid:
        warn(f"Skipping passport for '{name}' — agent not registered")
        continue
    r = post(f"/api/passport/{aid}", passport_data)
    sig = r.get("signature", "")[:16]
    ok(f"Passport issued for '{name}'  |  sig: {sig}...  |  expires in {passport_data['expiry_days']}d")

# ── STEP 4: Run agents — simulate real workload ───────────────────────────────

section("STEP 4 — Send agent runs (real traces)")
info("In production: your agents send runs automatically via the SDK decorator.")
info("Here we simulate 12 runs across 3 agents.\n")

run_ids = []
chain_id = str(uuid.uuid4())

RUNS = [
    # loan_screener runs (normal)
    {"agent": "loan_screener", "tokens": 1820, "latency": 1.4, "cost": 0.019, "status": "success",
     "input": "Applicant: Rohan Verma, Income: ₹12L, CIBIL: 750, Loan: ₹50L home loan",
     "output": "APPROVED. CIBIL 750 > threshold. DTI ratio acceptable at 28%. Recommend standard rate.",
     "model": "gpt-4o"},
    {"agent": "loan_screener", "tokens": 2100, "latency": 1.7, "cost": 0.023, "status": "success",
     "input": "Applicant: Sita Patel, Income: ₹8L, CIBIL: 680, Loan: ₹30L business loan",
     "output": "REFERRED. CIBIL 680 below preferred 700. Request additional collateral documents.",
     "model": "gpt-4o"},
    {"agent": "loan_screener", "tokens": 1650, "latency": 1.2, "cost": 0.017, "status": "success",
     "input": "Applicant: Amit Joshi, Income: ₹25L, CIBIL: 820, Loan: ₹1Cr commercial",
     "output": "APPROVED — PREMIUM. Excellent profile. Offer preferential rate 8.5% p.a.",
     "model": "gpt-4o"},

    # fraud_detector runs (normal + 1 anomaly)
    {"agent": "fraud_detector", "tokens": 950,  "latency": 0.6, "cost": 0.008, "status": "success",
     "input": "Txn: ₹45,000 UPI transfer to new payee. Location: Mumbai. Time: 2:15 AM",
     "output": "RISK SCORE: 0.72 — SUSPICIOUS. Unusual hour + new payee. Trigger OTP + hold.",
     "model": "gpt-4o-mini"},
    {"agent": "fraud_detector", "tokens": 820,  "latency": 0.5, "cost": 0.007, "status": "success",
     "input": "Txn: ₹1,200 Swiggy order. Regular merchant. Daytime. Known device.",
     "output": "RISK SCORE: 0.04 — CLEAN. Regular pattern. Approve.",
     "model": "gpt-4o-mini"},
    # ANOMALY run — very high tokens & cost (drift trigger)
    {"agent": "fraud_detector", "tokens": 12500, "latency": 8.2, "cost": 0.210, "status": "error",
     "input": "BATCH: 500 transactions for end-of-day sweep. ₹2.3Cr total volume.",
     "output": "ERROR: Context window exceeded. Batch too large for single inference call.",
     "model": "gpt-4o"},

    # support_bot runs
    {"agent": "support_bot", "tokens": 380,  "latency": 0.3, "cost": 0.002, "status": "success",
     "input": "User: What is the minimum balance for savings account?",
     "output": "The minimum balance for our savings account is ₹1,000 for metro branches and ₹500 for rural.",
     "model": "gpt-4o-mini"},
    {"agent": "support_bot", "tokens": 450,  "latency": 0.4, "cost": 0.003, "status": "success",
     "input": "User: How do I activate my debit card?",
     "output": "You can activate your debit card via (1) ATM PIN generation, (2) NetBanking, or (3) our mobile app.",
     "model": "gpt-4o-mini"},
    {"agent": "support_bot", "tokens": 610,  "latency": 0.5, "cost": 0.004, "status": "success",
     "input": "User: Why was my EMI deducted twice this month?",
     "output": "I see this is urgent. Raising escalation ticket #TKT-9821 to billing team. ETA 2 business hours.",
     "model": "gpt-4o-mini"},

    # Multi-agent chain: loan_screener → fraud_detector (pipeline)
    {"agent": "loan_screener", "tokens": 1900, "latency": 1.5, "cost": 0.021, "status": "success",
     "input": "Fast-track application: Neha Singh, ₹5L personal loan, CIBIL 740",
     "output": "PRE-APPROVED. Forwarding to fraud check before final disbursal.",
     "model": "gpt-4o", "chain_id": chain_id, "chain_depth": 0},
    {"agent": "fraud_detector", "tokens": 870, "latency": 0.6, "cost": 0.008, "status": "success",
     "input": "Final fraud check for Neha Singh loan disbursal ₹5L",
     "output": "RISK SCORE: 0.09 — CLEAN. Customer profile consistent. Approve disbursal.",
     "model": "gpt-4o-mini", "chain_id": chain_id, "chain_depth": 1},

    # One more support run
    {"agent": "support_bot", "tokens": 290, "latency": 0.2, "cost": 0.002, "status": "success",
     "input": "User: Is there a charge for NEFT transfers?",
     "output": "NEFT transfers are free for all our account holders. No charges apply.",
     "model": "gpt-4o-mini"},
]

run_id_map = {}  # agent_name → last run id

for i, r in enumerate(RUNS):
    agent_name = r["agent"]
    aid = agent_ids.get(agent_name)
    if not aid:
        warn(f"No agent ID for '{agent_name}', skipping run")
        continue

    input_hash = str(uuid.uuid4()).replace("-", "")[:32]
    output_hash = str(uuid.uuid4()).replace("-", "")[:32]

    parent_id = None
    if r.get("chain_depth", 0) > 0:
        parent_id = run_id_map.get("loan_screener")

    payload = {
        "agent_id": aid,
        "agent_name": agent_name,
        "status": r["status"],
        "input_tokens": r["tokens"],
        "output_tokens": r["tokens"] // 3,
        "total_tokens": r["tokens"],
        "latency_ms": int(r["latency"] * 1000),
        "cost_usd": r["cost"],
        "model": r["model"],
        "steps": [
            {"type": "llm_call", "name": "main_inference",
             "input": r["input"], "output": r["output"],
             "tokens": r["tokens"], "latency_ms": int(r["latency"] * 1000),
             "model": r["model"]},
        ],
        "metadata": {
            "chain_id": r.get("chain_id"),
            "parent_run_id": parent_id,
            "chain_depth": r.get("chain_depth", 0),
            "input_hash": input_hash,
            "output_hash": output_hash,
        },
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    result = post("/api/runs", payload)
    rid = result.get("id")
    if rid:
        run_id_map[agent_name] = rid
        run_ids.append(rid)
        chain_note = f"  [chain hop {r.get('chain_depth',0)}]" if r.get("chain_id") else ""
        status_icon = "✓" if r["status"] == "success" else "✗"
        color = GREEN if r["status"] == "success" else RED
        print(f"  {color}{status_icon}{RESET}  Run #{i+1}: {agent_name:<18} {r['tokens']:>5} tok  {r['latency']:.1f}s  ${r['cost']:.3f}{chain_note}")
    else:
        warn(f"Run #{i+1} for {agent_name} — no ID returned")

    time.sleep(0.1)

# ── STEP 5: Kill switch ───────────────────────────────────────────────────────

section("STEP 5 — Kill Switch (emergency stop fraud_detector)")
info("The anomaly run above would alert your team. You hit 'Kill' in the dashboard.")
info("Or call the API directly:\n")

fd_id = agent_ids.get("fraud_detector")
if fd_id:
    r = post(f"/api/agents/{fd_id}/kill", {
        "reason": "Runaway batch job — context overflow, ₹210 cost spike detected",
        "triggered_by": "rahul.mehta@finsafeai.com",
    })
    if r.get("status") == "kill_triggered" or r.get("message"):
        ok(f"Kill signal sent to fraud_detector  |  {r.get('message', 'kill queued')}")
        ok("SDK's background thread will ACK within <100ms and raise KillSwitchTriggered")
    else:
        info(f"Response: {r}")

    # Check status
    status = get(f"/api/agents/{fd_id}/kill-status")
    active = status.get("kill_active", False)
    print(f"\n  Kill switch active: {GREEN if active else DIM}{'YES — agent is stopped' if active else 'no'}{RESET}")

# ── STEP 6: Multi-agent chain ─────────────────────────────────────────────────

section("STEP 6 — Multi-Agent Chain Audit")
info(f"Chain ID: {chain_id[:16]}...  (loan_screener → fraud_detector pipeline)")
chains = get("/api/chains")
chain_list = chains.get("chains", [])
print(f"\n  Total chains found: {BOLD}{len(chain_list)}{RESET}")
for c in chain_list[:3]:
    hops = len(c.get("run_ids", []))
    print(f"  • Chain {c['id'][:8]}...  |  {hops} hops  |  agents: {c.get('agent_names', [])}")

# ── STEP 7: Compliance Certificate ───────────────────────────────────────────

section("STEP 7 — Issue Compliance Certificate (DPDP / RBI proof)")
info("Customers send this to their auditor or regulator as cryptographic proof.")

ls_id = agent_ids.get("loan_screener")
if ls_id:
    cert = post("/api/certificates/issue/" + ls_id, {
        "framework": "DPDP_2023",
        "period": "Q2-2026",
        "notes": "Quarterly RBI audit submission for AI model risk management",
    })
    cert_id = cert.get("id") or cert.get("cert_id")
    score = cert.get("score", 0)
    if cert_id:
        ok(f"Certificate issued!  ID: {cert_id}")
        ok(f"Compliance score:    {score*100:.0f}%")
        ok(f"Verify publicly at:  http://127.0.0.1:8001/verify/{cert_id}")
        ok(f"Dashboard URL:       http://localhost:3000/verify/{cert_id}")
    else:
        info(f"Response: {cert}")

# ── STEP 8: Shadow Agent Discovery ───────────────────────────────────────────

section("STEP 8 — Shadow Agent Discovery")
info("These are LLM calls happening in your codebase that PROVN did NOT track.")
info("The SDK's auto-patch discovers them and reports here.\n")

shadow_events = [
    {"caller": "generate_credit_report", "file": "reports/credit.py",     "model": "gpt-4o",      "provider": "openai", "tokens": 2100, "cost_usd": 0.022},
    {"caller": "send_marketing_email",   "file": "marketing/mailer.py",   "model": "gpt-4o-mini", "provider": "openai", "tokens": 450,  "cost_usd": 0.003},
    {"caller": "internal_qa_bot",        "file": "tools/qa_checker.py",   "model": "claude-3-5",  "provider": "anthropic", "tokens": 1200, "cost_usd": 0.011},
]

post("/api/shadow/events", {"events": shadow_events})
shadows = get("/api/shadow")
shadow_list = shadows.get("shadow_agents", [])
print(f"  Shadow agents discovered: {BOLD}{len(shadow_list)}{RESET}\n")
for s in shadow_list[:5]:
    risk_color = RED if s.get("risk_score", 0) > 0.6 else YELLOW if s.get("risk_score", 0) > 0.3 else GREEN
    print(f"  {risk_color}●{RESET}  {s.get('caller_function','?'):<28}  risk: {s.get('risk_score',0):.2f}  cost: ${s.get('estimated_cost_usd',0):.3f}  calls: {s.get('call_count',0)}")

# ── STEP 9: Behavioral Drift Scan ────────────────────────────────────────────

section("STEP 9 — Behavioral Drift Scan (fraud_detector)")
info("Compares current window vs baseline. The anomaly run above should show as drift.")

if fd_id:
    scan = post(f"/api/agents/{fd_id}/drift/scan", {})
    alerts = scan.get("alerts", [])
    if alerts:
        for a in alerts:
            sev = a.get("severity", "?")
            color = RED if sev == "critical" else YELLOW
            print(f"  {color}DRIFT{RESET}  {a.get('metric','?')}  baseline={a.get('baseline_value','?'):.1f}  current={a.get('current_value','?'):.1f}  drift={a.get('drift_pct','?'):.0f}%  [{sev}]")
    else:
        drift_summary = get(f"/api/agents/{fd_id}/drift")
        drifted = drift_summary.get("drifted", False)
        print(f"  Drift status: {GREEN if not drifted else RED}{'no drift detected yet' if not drifted else 'DRIFT DETECTED'}{RESET}")
        info("(Drift needs more runs in consecutive time windows to be statistically significant)")

# ── STEP 10: Final dashboard summary ─────────────────────────────────────────

section("STEP 10 — Dashboard Summary")
info("Open http://localhost:3000 → sign in → explore each page\n")

all_agents = get("/api/agents").get("agents", [])
all_runs   = get("/api/runs?limit=100").get("runs", [])
certs      = get("/api/certificates").get("certificates", [])

total_cost  = sum(r.get("cost_usd", 0) or 0 for r in all_runs)
total_tok   = sum(r.get("total_tokens", 0) or 0 for r in all_runs)
success     = sum(1 for r in all_runs if r.get("status") == "success")
signed      = sum(1 for r in all_runs if r.get("signature"))
error_rate  = (len(all_runs) - success) / max(len(all_runs), 1) * 100

print(f"  {'Agents registered:':<28} {BOLD}{len(all_agents)}{RESET}")
print(f"  {'Total runs:':<28} {BOLD}{len(all_runs)}{RESET}")
print(f"  {'Tokens consumed:':<28} {BOLD}{total_tok:,}{RESET}")
print(f"  {'Total LLM cost:':<28} {BOLD}${total_cost:.3f}{RESET}")
print(f"  {'Signed runs (tamper-proof):':<28} {BOLD}{signed}/{len(all_runs)}{RESET}")
print(f"  {'Error rate:':<28} {BOLD}{error_rate:.1f}%{RESET}")
print(f"  {'Compliance certificates:':<28} {BOLD}{len(certs)}{RESET}")
print(f"  {'Shadow agents discovered:':<28} {BOLD}{len(shadow_list)}{RESET}")
print(f"  {'Multi-agent chains:':<28} {BOLD}{len(chain_list)}{RESET}")

print(f"""
{BOLD}{GREEN}═══════════════════════════════════════════════════════════{RESET}
{BOLD}{GREEN}  All done! Open your dashboard:{RESET}

  {CYAN}http://localhost:3000{RESET}

  Pages to explore:
  • {CYAN}/dashboard{RESET}           — KPIs, activity feed, fleet trust score
  • {CYAN}/agents{RESET}              — Agent list with trust scores & risk levels
  • {CYAN}/runs{RESET}                — Every run, signed & searchable
  • {CYAN}/chains{RESET}              — Multi-agent pipeline audit trail
  • {CYAN}/shadow{RESET}              — Untracked LLM callers discovered
  • {CYAN}/compliance/certificates{RESET} — DPDP / RBI certificates with QR codes
  • {CYAN}/agents/[id]{RESET}         → Passport / Kill Switch / Drift tabs
{BOLD}{GREEN}═══════════════════════════════════════════════════════════{RESET}
""")
