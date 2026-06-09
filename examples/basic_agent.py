"""
PROVN SDK — basic usage example.

Run this after starting the PROVN backend:
    cd trustlayer && docker-compose up -d
    cd sdk && pip install -e .
    TRUSTLAYER_HUMAN_SPONSOR=you@company.com python examples/basic_agent.py
"""
import os
import time
import random

os.environ.setdefault("TRUSTLAYER_API_KEY", "dev-key-123")
os.environ.setdefault("TRUSTLAYER_API_URL", "http://localhost:8000")
os.environ.setdefault("TRUSTLAYER_HUMAN_SPONSOR", "demo@company.com")

from trustlayer import PROVNTracker

tracker = PROVNTracker(
    agent_name="demo-crm-summarizer",
    agent_version="1.0.0",
    human_sponsor="demo@company.com",
)


@tracker.track
def run_crm_summarizer(customer_id: str) -> dict:
    """Simulate a CRM summarizer agent with multiple LLM + tool steps."""

    # Step 1: Tool call — fetch customer from CRM
    with tracker.tool_call("fetch_customer", {"customer_id": customer_id}) as step:
        time.sleep(0.1)
        customer_data = {
            "id": customer_id,
            "name": "Acme Corp",
            "arr": 42000,
            "open_tickets": 3,
            "last_contact": "2026-04-15",
        }
        step.tool_result = customer_data

    # Step 2: LLM call — summarize
    with tracker.llm_call("Summarize customer data", "gpt-4o-mini") as step:
        time.sleep(0.2)
        tokens_used = random.randint(300, 600)
        step.prompt_tokens = tokens_used
        step.completion_tokens = random.randint(80, 150)
        step.cost_usd = (step.prompt_tokens * 0.00000015) + (step.completion_tokens * 0.0000006)

    # Step 3: Tool call — send summary email
    with tracker.tool_call("send_email", {"to": "sales@company.com", "subject": f"CRM update: {customer_id}"}) as step:
        time.sleep(0.05)
        step.tool_result = {"status": "sent", "message_id": "msg_abc123"}

    return {"summary": f"Customer {customer_id} processed", "status": "success"}


if __name__ == "__main__":
    print("Running demo agent with PROVN tracking...")
    print("Every run is signed and sent to the PROVN dashboard.\n")

    for i in range(3):
        result = run_crm_summarizer(customer_id=f"CUST-{1000 + i}")
        print(f"  Run {i+1}: {result}")
        time.sleep(0.5)

    print("\nDone. Open http://localhost:3000 to see your agent runs.")
