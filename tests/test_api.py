"""End-to-end over HTTP, including the audit chain and the demo script itself."""

from __future__ import annotations

from .conftest import PURCHASE_SCOPE


def request_and_approve(api, scope=None, ttl_seconds=86400):
    created = api.post(
        "/api/requests",
        json={
            "requested_by": "agent:consent-agent-7f3a",
            "purpose": "buy the book you asked about",
            "scope": scope or PURCHASE_SCOPE,
            "ttl_seconds": ttl_seconds,
        },
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["request_id"]
    approved = api.post(f"/api/requests/{request_id}/approve", json={"note": "ok"})
    assert approved.status_code == 200, approved.text
    return approved.json()["grant"]


# --------------------------------------------------------------------------- #
# the demo script, start to finish
# --------------------------------------------------------------------------- #


def test_full_demo_script(api):
    # 1. agent requests scope, rendered in plain language
    created = api.post(
        "/api/requests",
        json={
            "requested_by": "agent:consent-agent-7f3a",
            "purpose": "buy the book you asked about",
            "scope": PURCHASE_SCOPE,
            "ttl_seconds": 86400,
        },
    ).json()
    assert "spend your money" in created["summary"]
    assert any("$30.00 in any one action" in c for c in created["clauses"])

    # 2. human approves -> signed token minted
    grant = api.post(
        f"/api/requests/{created['request_id']}/approve", json={"note": "sure"}
    ).json()["grant"]
    assert grant["signature"]["alg"] == "Ed25519"

    # 3. agent presents token to merchant -> purchase succeeds
    ok = api.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "bk-001", "action_id": "act-1"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["receipt"]["charged"] == "would have charged $18.00"

    # 4. human revokes
    api.post(f"/api/grants/{grant['token_id']}/revoke", json={"reason": "done"})

    # 5. agent tries again -> denied
    denied = api.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "bk-002", "action_id": "act-2"},
    )
    assert denied.status_code == 403
    assert denied.json()["decision"]["code"] == "revoked"

    # 6. audit trail records every step, and the chain verifies
    audit = api.get("/api/audit").json()
    events = [e["event"] for e in audit["entries"]]
    assert events == [
        "scope_requested",
        "consent_granted",
        "verification_allowed",
        "consent_revoked",
        "verification_denied",
    ]
    assert audit["chain"]["intact"] is True
    assert audit["chain"]["length"] == 5


def test_merchant_prices_the_action_not_the_agent(api):
    """The agent picks an item; the merchant fills in the amount and its own domain.

    An agent that could assert `amount_usd` itself could under-report it.
    """
    grant = request_and_approve(api)
    body = api.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "bk-002", "action_id": "a1"},
    ).json()
    assert body["action"]["amount_usd"] == "22.50"
    assert body["action"]["merchant"] == "demo-bookstore.com"


def test_out_of_scope_item_denied_over_http(api):
    grant = request_and_approve(api)
    # bk-004 costs $48, over the $30 per-transaction cap
    over = api.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "bk-004", "action_id": "a1"},
    )
    assert over.status_code == 403
    assert over.json()["decision"]["code"] == "over_per_action_limit"

    # el-001 is $24 but the wrong category
    wrong = api.post(
        "/merchant/purchase",
        json={"grant": grant, "item_id": "el-001", "action_id": "a2"},
    )
    assert wrong.status_code == 403
    assert wrong.json()["decision"]["code"] == "not_in_allowlist"


def test_preview_does_not_consume_a_use(api):
    grant = request_and_approve(api)
    for _ in range(5):
        api.post("/merchant/preview", json={"grant": grant, "item_id": "bk-001"})
    view = api.get(f"/api/grants/{grant['token_id']}").json()
    uses = next(r for r in view["remaining"] if r["label"] == "Uses")
    assert uses["used"] == 0


def test_grant_view_reports_remaining_budget(api):
    grant = request_and_approve(api)
    api.post("/merchant/purchase", json={"grant": grant, "item_id": "bk-002", "action_id": "a1"})
    view = api.get(f"/api/grants/{grant['token_id']}").json()
    assert view["state"] == "active"
    budget = next(r for r in view["remaining"] if r["label"] == "Budget")
    assert budget["display"] == "$22.50 of $50.00 spent"


def test_inexpressible_scope_rejected_with_422(api):
    bad = api.post(
        "/api/requests",
        json={
            "requested_by": "agent:x",
            "purpose": "",
            "scope": {"action_type": "purchase", "constraints": {"max_uses": 1}},
        },
    )
    assert bad.status_code == 422
    assert "merchant_allowlist" in bad.json()["detail"]


def test_denied_request_mints_nothing(api):
    created = api.post(
        "/api/requests",
        json={"requested_by": "agent:x", "purpose": "", "scope": PURCHASE_SCOPE},
    ).json()
    api.post(f"/api/requests/{created['request_id']}/deny", json={"note": "no thanks"})
    assert api.get("/api/grants").json() == []
    events = [e["event"] for e in api.get("/api/audit").json()["entries"]]
    assert events == ["scope_requested", "consent_denied"]


def test_vocabulary_lists_all_four_action_types(api):
    vocab = api.get("/api/vocabulary").json()
    assert {a["action_type"] for a in vocab["action_types"]} == {
        "purchase",
        "send_message",
        "edit_resource",
        "api_call",
    }


def test_preview_endpoint_renders_plain_language(api):
    body = api.post("/api/preview", json={"scope": PURCHASE_SCOPE}).json()
    assert body["valid"] is True
    assert "only merchant demo-bookstore.com" in body["clauses"][0]


# --------------------------------------------------------------------------- #
# audit chain
# --------------------------------------------------------------------------- #


def test_audit_chain_links_every_entry(api):
    grant = request_and_approve(api)
    api.post("/merchant/purchase", json={"grant": grant, "item_id": "bk-001", "action_id": "a1"})
    entries = api.get("/api/audit").json()["entries"]
    assert entries[0]["prev_hash"] == "0" * 64
    for previous, current in zip(entries, entries[1:]):
        assert current["prev_hash"] == previous["row_hash"]


def test_tampering_with_a_past_entry_breaks_the_chain(api):
    grant = request_and_approve(api)
    api.post("/merchant/purchase", json={"grant": grant, "item_id": "bk-001", "action_id": "a1"})
    assert api.get("/api/audit/verify").json()["intact"] is True

    tampered = api.post("/api/demo/tamper/2").json()
    assert tampered["chain"]["intact"] is False
    assert tampered["chain"]["broken_at"] == 2
    assert "altered" in tampered["chain"]["detail"]


def test_deleting_an_entry_breaks_the_chain(api):
    grant = request_and_approve(api)
    api.post("/merchant/purchase", json={"grant": grant, "item_id": "bk-001", "action_id": "a1"})
    store = api.app.state.store
    with store.write_txn() as conn:
        conn.execute("DELETE FROM audit_log WHERE seq = 2")
    report = api.get("/api/audit/verify").json()
    assert report["intact"] is False
    assert "removed or inserted" in report["detail"]


def test_denials_are_audited_with_their_reason(api):
    grant = request_and_approve(api)
    api.post("/merchant/purchase", json={"grant": grant, "item_id": "bk-004", "action_id": "a1"})
    entries = api.get("/api/audit").json()["entries"]
    denial = next(e for e in entries if e["event"] == "verification_denied")
    assert denial["payload"]["code"] == "over_per_action_limit"
    assert denial["actor"] == "demo-bookstore.com"


def test_reset_clears_everything(api):
    request_and_approve(api)
    api.post("/api/demo/reset")
    assert api.get("/api/grants").json() == []
    assert api.get("/api/audit").json()["entries"] == []
    assert api.get("/api/audit/verify").json()["intact"] is True
