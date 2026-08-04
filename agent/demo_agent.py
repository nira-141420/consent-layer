"""A simulated agent that walks the demo script end to end.

Two uses. It is the narrated CLI version of the demo (the fallback in section 8 of
the proposal), and it is a smoke test that the whole system works against a real
server rather than a test client.

    python agent/demo_agent.py                 # against http://127.0.0.1:8000
    python agent/demo_agent.py --pause         # stop between beats, for narrating
    python agent/demo_agent.py --url http://…  # somewhere else

There is no LLM here on purpose. What an agent "wants" is not the interesting
part; what it can be *stopped* from doing is.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import httpx

AGENT = "agent:consent-agent-7f3a"

SCOPE = {
    "action_type": "purchase",
    "constraints": {
        "merchant_allowlist": ["demo-bookstore.com"],
        "category": ["books"],
        "max_single_transaction_usd": 30,
        "max_amount_usd": 50,
        "max_uses": 3,
        "currency": "USD",
    },
}

# Windows terminals need this nudged on before they honour ANSI.
if os.name == "nt":
    os.system("")

DIM, BOLD, RESET = "\033[2m", "\033[1m", "\033[0m"
GREEN, RED, BLUE, YELLOW = "\033[32m", "\033[31m", "\033[34m", "\033[33m"


class Narrator:
    def __init__(self, pause: bool) -> None:
        self.pause = pause
        self.step = 0

    def beat(self, title: str) -> None:
        self.step += 1
        print(f"\n{BOLD}{BLUE}▸ {self.step}. {title}{RESET}")
        if self.pause:
            input(f"{DIM}   [enter]{RESET}")

    @staticmethod
    def say(text: str, colour: str = "") -> None:
        print(f"   {colour}{text}{RESET}")

    @staticmethod
    def allowed(text: str) -> None:
        print(f"   {GREEN}✓ {text}{RESET}")

    @staticmethod
    def denied(text: str) -> None:
        print(f"   {RED}✕ {text}{RESET}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--pause", action="store_true", help="wait for enter between beats")
    parser.add_argument("--keep", action="store_true", help="do not reset the demo first")
    args = parser.parse_args()

    narrator = Narrator(args.pause)
    client = httpx.Client(base_url=args.url, timeout=10.0)

    try:
        client.get("/api/vocabulary")
    except httpx.ConnectError:
        print(f"{RED}Cannot reach the consent layer at {args.url}.{RESET}")
        print(f"{DIM}Start it with:  python -m uvicorn consent_layer.app:app --reload{RESET}")
        return 1

    if not args.keep:
        client.post("/api/demo/reset")

    print(f"{BOLD}Consent Layer — demo{RESET}")
    print(f"{DIM}agent: {AGENT}   merchant: demo-bookstore.com{RESET}")

    # ── 1 ────────────────────────────────────────────────────────────────
    narrator.beat("The agent asks for a narrow permission")
    created = client.post(
        "/api/requests",
        json={
            "requested_by": AGENT,
            "purpose": "You asked me to pick up a copy of the book we discussed.",
            "scope": SCOPE,
            "ttl_seconds": 86400,
        },
    ).json()
    narrator.say(created["summary"], BOLD)
    for clause in created["clauses"]:
        narrator.say(f"  · {clause}", DIM)
    narrator.say(f"  · expires after {created['duration']}", DIM)

    # ── 2 ────────────────────────────────────────────────────────────────
    narrator.beat("You approve it — a signed token is minted")
    grant = client.post(
        f"/api/requests/{created['request_id']}/approve", json={"note": "approved in demo"}
    ).json()["grant"]
    narrator.say(f"token_id  {grant['token_id']}")
    narrator.say(f"signature {grant['signature']['alg']} · {grant['signature']['value'][:44]}…", DIM)
    narrator.say(f"expires   {grant['expires_at']}", DIM)

    # ── 3 ────────────────────────────────────────────────────────────────
    narrator.beat("The agent buys a book — the merchant verifies independently")
    response = client.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "bk-001", "action_id": "act-demo-1"},
    )
    body = response.json()
    for check in body["decision"]["checks"]:
        mark = f"{GREEN}✓" if check["passed"] else f"{RED}✕"
        print(f"     {mark} {check['name']}{RESET}{DIM} {check.get('detail', '')}{RESET}")
    narrator.allowed(body["receipt"]["charged"])

    # ── 4 ────────────────────────────────────────────────────────────────
    narrator.beat("The same token cannot be stretched beyond what you approved")
    over = client.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "bk-004", "action_id": "act-demo-2"},
    ).json()
    narrator.denied(f"$48 encyclopaedia — {over['decision']['reason']}")

    wrong = client.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "el-001", "action_id": "act-demo-3"},
    ).json()
    narrator.denied(f"headphones — {wrong['decision']['reason']}")

    tampered = dict(grant)
    tampered["scope"] = {
        **grant["scope"],
        "constraints": {**grant["scope"]["constraints"], "max_single_transaction_usd": 5000},
    }
    forged = client.post(
        "/merchant/purchase",
        json={"grant": tampered, "item_id": "bk-004", "action_id": "act-demo-4"},
    ).json()
    narrator.denied(f"edited token — {forged['decision']['reason']}")

    # ── 5 ────────────────────────────────────────────────────────────────
    narrator.beat("You revoke the permission")
    client.post(f"/api/grants/{grant['token_id']}/revoke", json={"reason": "changed my mind"})
    narrator.say("revoked", YELLOW)

    # ── 6 ────────────────────────────────────────────────────────────────
    narrator.beat("The agent tries again — denied immediately")
    after = client.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "bk-002", "action_id": "act-demo-5"},
    ).json()
    narrator.denied(after["decision"]["reason"])

    # ── 7 ────────────────────────────────────────────────────────────────
    narrator.beat("Every step is on the audit trail, and the chain verifies")
    audit = client.get("/api/audit").json()
    for entry in audit["entries"]:
        print(
            f"   {DIM}{entry['seq']:>2}{RESET}  {entry['event']:<22}"
            f" {DIM}{entry['actor']:<26} {entry['row_hash'][:10]}…{RESET}"
        )
    chain = audit["chain"]
    narrator.allowed(f"chain intact — {chain['detail']}")

    # ── 8 ────────────────────────────────────────────────────────────────
    narrator.beat("Edit one historic entry and the chain says so")
    target = next(e for e in audit["entries"] if e["event"] == "consent_granted")
    result = client.post(f"/api/demo/tamper/{target['seq']}").json()
    narrator.say(f"edited entry {target['seq']} directly in the database", YELLOW)
    narrator.denied(result["chain"]["detail"])

    print(f"\n{DIM}Reset with:  curl -X POST {args.url}/api/demo/reset{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
