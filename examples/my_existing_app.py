"""
============================================================
  SCENARIO: You are a developer at "FinSafeAI"
  You already have 3 AI agents running in production.
  You want to add PROVN governance on top of them.

  BEFORE PROVN  →  lines marked  # (BEFORE)
  AFTER  PROVN  →  lines marked  # ← NEW (the only changes)

  That's it. 3 lines added. Zero code rewritten.
============================================================
"""

# ── 1. Your existing imports (unchanged) ──────────────────
import time
import random

# ── 2. ADD THESE 3 LINES  ← NEW ───────────────────────────
import trustlayer as tl
tracker = tl.init(
    api_key="tl_live_7a9851c5dcb6e2036aba5df9c5bf266c0434c7a7",
    api_url="http://127.0.0.1:8001",
    human_sponsor="rahul.mehta@finsafeai.com",   # who owns these agents
)
# ──────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════
#  AGENT 1 — Loan Screener
#  Your existing code is 100% untouched.
#  You just added @tl.track above the function.
# ══════════════════════════════════════════════════════════

@tl.track   # ← NEW — this single line adds full observability
def loan_screener(applicant_name: str, cibil: int, income_lpa: float, loan_amount: float):
    """
    YOUR EXISTING CODE — not a single line changed inside.
    This is exactly what you had before PROVN.
    """
    print(f"  [loan_screener] Evaluating {applicant_name}...")

    # Simulate your existing LLM call (e.g. openai.chat.completions.create)
    time.sleep(random.uniform(0.8, 1.6))

    # Your existing business logic
    if cibil >= 750 and income_lpa >= 10:
        decision = "APPROVED"
        rate     = 8.5
        reason   = f"Excellent profile: CIBIL {cibil}, income ₹{income_lpa}L p.a."
    elif cibil >= 680:
        decision = "REFERRED"
        rate     = None
        reason   = f"CIBIL {cibil} below preferred 700. Request collateral docs."
    else:
        decision = "REJECTED"
        rate     = None
        reason   = f"CIBIL {cibil} too low. Minimum 650 required."

    return {
        "applicant": applicant_name,
        "decision":  decision,
        "rate":      rate,
        "reason":    reason,
    }


# ══════════════════════════════════════════════════════════
#  AGENT 2 — Fraud Detector
#  Same pattern — one decorator, nothing else changes.
# ══════════════════════════════════════════════════════════

@tl.track   # ← NEW
def fraud_detector(txn_id: str, amount: float, merchant: str, hour: int, is_new_payee: bool):
    """Your existing fraud detection logic — unchanged."""
    print(f"  [fraud_detector] Checking txn {txn_id} ₹{amount:,.0f}...")

    time.sleep(random.uniform(0.3, 0.7))

    risk_score = 0.05
    if hour < 6 or hour > 23:
        risk_score += 0.35      # unusual time
    if is_new_payee:
        risk_score += 0.25      # new payee
    if amount > 50_000:
        risk_score += 0.20      # large amount

    if risk_score >= 0.6:
        action = "BLOCK_AND_ALERT"
    elif risk_score >= 0.35:
        action = "OTP_VERIFY"
    else:
        action = "APPROVE"

    return {"txn_id": txn_id, "risk_score": round(risk_score, 2), "action": action}


# ══════════════════════════════════════════════════════════
#  AGENT 3 — Support Bot
#  Low-risk, minimal governance needed. @tl.track is enough.
# ══════════════════════════════════════════════════════════

@tl.track   # ← NEW
def support_bot(user_id: str, query: str):
    """Your existing support bot — unchanged."""
    print(f"  [support_bot] Answering: '{query[:50]}...'")

    time.sleep(random.uniform(0.2, 0.5))

    answers = {
        "minimum balance":  "Minimum balance is ₹1,000 (metro) / ₹500 (rural).",
        "neft charges":     "NEFT transfers are completely free for all customers.",
        "debit card":       "Activate via ATM, NetBanking, or the mobile app.",
        "emi deducted":     "Raising escalation ticket to billing. ETA: 2 business hours.",
    }

    for key, answer in answers.items():
        if key in query.lower():
            return {"user_id": user_id, "response": answer}

    return {"user_id": user_id, "response": "Let me connect you with a human agent."}


# ══════════════════════════════════════════════════════════
#  YOUR EXISTING main() — COMPLETELY UNCHANGED
#  PROVN captures everything silently in the background
# ══════════════════════════════════════════════════════════

def main():
    print("\n" + "="*60)
    print("  FinSafeAI — Production Run (PROVN enabled)")
    print("="*60)
    print()

    print("▶ Running Loan Screener agent (3 applications)...")
    results = [
        loan_screener("Rohan Verma",  cibil=780, income_lpa=15.0, loan_amount=5_000_000),
        loan_screener("Sita Patel",   cibil=690, income_lpa=8.5,  loan_amount=3_000_000),
        loan_screener("Deepak Nair",  cibil=620, income_lpa=6.0,  loan_amount=2_000_000),
    ]
    for r in results:
        icon = "✓" if r["decision"] == "APPROVED" else ("⚠" if r["decision"] == "REFERRED" else "✗")
        print(f"    {icon}  {r['applicant']:<15}  {r['decision']}")

    print()
    print("▶ Running Fraud Detector agent (5 transactions)...")
    txns = [
        fraud_detector("TXN001", amount=1_200,  merchant="Swiggy",       hour=13, is_new_payee=False),
        fraud_detector("TXN002", amount=45_000, merchant="New Payee",    hour=2,  is_new_payee=True),
        fraud_detector("TXN003", amount=8_500,  merchant="Amazon",       hour=11, is_new_payee=False),
        fraud_detector("TXN004", amount=75_000, merchant="Unknown",      hour=3,  is_new_payee=True),
        fraud_detector("TXN005", amount=350,    merchant="BookMyShow",   hour=19, is_new_payee=False),
    ]
    for t in txns:
        icon = "✓" if t["action"] == "APPROVE" else ("⚠" if t["action"] == "OTP_VERIFY" else "✗")
        print(f"    {icon}  {t['txn_id']}  risk={t['risk_score']:.2f}  →  {t['action']}")

    print()
    print("▶ Running Support Bot agent (3 queries)...")
    queries = [
        support_bot("U001", "What is the minimum balance for savings?"),
        support_bot("U002", "Is there any NEFT charges?"),
        support_bot("U003", "My EMI was deducted twice this month"),
    ]
    for q in queries:
        print(f"    ✓  {q['user_id']}  →  {q['response'][:60]}...")

    print()
    print("="*60)
    print("  All done. Now open your dashboard:")
    print("  → http://localhost:3000")
    print()
    print("  What PROVN captured automatically:")
    print("  • 11 agent runs with full traces")
    print("  • Every run cryptographically signed (Ed25519)")
    print("  • Behavioral fingerprint updated for each agent")
    print("  • Anomaly detection ran on every run")
    print("  • Compliance score calculated (DPDP + RBI)")
    print("  • Any untracked LLM calls also captured (shadow agents)")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
