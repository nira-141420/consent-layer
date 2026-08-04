"""The security properties of verification.

Each test here corresponds to a way the system could quietly grant more authority
than the human agreed to. Those are the failures that matter -- an over-eager
denial is an annoyance, an over-eager approval is the whole problem.
"""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from consent_layer.consent import ConsentLayer
from consent_layer.crypto import Keyring
from consent_layer.db import Store, from_iso, to_iso
from consent_layer.sdl import ScopeError
from consent_layer.verifier import LocalRevocationSource, Verifier

from .conftest import PURCHASE_SCOPE, buy


# --------------------------------------------------------------------------- #
# the happy path
# --------------------------------------------------------------------------- #


def test_approved_purchase_within_scope_is_allowed(granted, verifier):
    grant = granted()
    decision = verifier.verify(grant, buy("18.00"))
    assert decision.allowed, decision.reason
    assert [c.passed for c in decision.checks] == [True] * 8


def test_grant_is_signed_and_verifies(granted, keyring):
    grant = granted()
    ok, why = keyring.verify_grant(grant)
    assert ok, why
    assert grant["signature"]["alg"] == "Ed25519"


# --------------------------------------------------------------------------- #
# signature integrity
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda g: g["scope"]["constraints"].update(max_single_transaction_usd=5000),
            id="raise-the-spending-cap",
        ),
        pytest.param(
            lambda g: g["scope"]["constraints"]["merchant_allowlist"].append("evil.example"),
            id="add-a-merchant",
        ),
        pytest.param(
            lambda g: g["scope"]["constraints"].update(max_uses=999),
            id="raise-max-uses",
        ),
        pytest.param(
            lambda g: g.update(expires_at="2099-01-01T00:00:00Z"),
            id="extend-the-expiry",
        ),
        pytest.param(
            lambda g: g["scope"]["constraints"].pop("max_amount_usd"),
            id="delete-the-budget",
        ),
        pytest.param(lambda g: g.update(issued_to="agent:someone-else"), id="change-holder"),
    ],
)
def test_any_edit_to_a_grant_breaks_its_signature(granted, verifier, mutate):
    """An agent holding a token must not be able to widen it."""
    grant = copy.deepcopy(granted())
    mutate(grant)
    decision = verifier.verify(grant, buy("18.00"))
    assert not decision.allowed
    assert decision.code == "bad_signature"


def test_unsigned_grant_rejected(granted, verifier):
    grant = copy.deepcopy(granted())
    grant["signature"] = {"alg": "none", "key_id": "x", "value": ""}
    decision = verifier.verify(grant, buy("18.00"))
    assert not decision.allowed
    assert decision.code == "bad_signature"
    assert "unsupported signature algorithm" in decision.reason


def test_grant_signed_by_a_stranger_rejected(granted, store, keyring):
    """A valid signature from the wrong key is not a valid signature."""
    attacker = Keyring(b"\x09" * 32, "user:priya@domain.com#key1")
    forged = ConsentLayer(store=store, keyring=attacker)._mint(
        {"scope": PURCHASE_SCOPE, "requested_by": "agent:evil", "ttl_seconds": 3600}
    )
    honest_verifier = Verifier(
        "demo-bookstore.com", keyring, LocalRevocationSource(store), store=store
    )
    decision = honest_verifier.verify(forged, buy("18.00"))
    assert not decision.allowed
    assert decision.code in ("bad_signature", "unknown_token")


# --------------------------------------------------------------------------- #
# scope enforcement
# --------------------------------------------------------------------------- #


def test_over_per_transaction_cap_denied(granted, verifier):
    decision = verifier.verify(granted(), buy("48.00"))
    assert not decision.allowed
    assert decision.code == "over_per_action_limit"
    assert "$30.00" in decision.reason


def test_wrong_category_denied(granted, verifier):
    decision = verifier.verify(granted(), buy("24.00", category="electronics"))
    assert not decision.allowed
    assert decision.code == "not_in_allowlist"


def test_wrong_merchant_denied(granted, verifier):
    decision = verifier.verify(granted(), buy("18.00", merchant="sketchy.example"))
    assert not decision.allowed
    assert decision.code == "not_in_allowlist"


def test_wrong_action_type_denied(granted, verifier):
    """A purchase permission is not a messaging permission."""
    action = buy("18.00")
    action["type"] = "send_message"
    decision = verifier.verify(granted(), action)
    assert not decision.allowed
    assert decision.code == "action_type_mismatch"


def test_denied_attempt_does_not_consume_a_use(granted, verifier, store):
    grant = granted()
    verifier.verify(grant, buy("48.00", action_id="a"))  # over cap
    verifier.verify(grant, buy("48.00", action_id="b"))  # over cap again
    assert verifier.verify(grant, buy("18.00", action_id="c")).allowed
    allowed = [r for r in store.redemptions_for(grant["token_id"]) if r["allowed"]]
    assert len(allowed) == 1


# --------------------------------------------------------------------------- #
# usage limits
# --------------------------------------------------------------------------- #


def test_max_uses_exhausts(granted, verifier):
    grant = granted()
    for i in range(3):
        assert verifier.verify(grant, buy("10.00", action_id=f"a{i}")).allowed
    decision = verifier.verify(grant, buy("10.00", action_id="a3"))
    assert not decision.allowed
    assert decision.code == "uses_exhausted"


def test_cumulative_budget_enforced_across_uses(granted, verifier):
    """Three purchases under the $30 per-transaction cap still cannot exceed $50."""
    grant = granted()
    assert verifier.verify(grant, buy("28.00", action_id="a")).allowed
    assert verifier.verify(grant, buy("20.00", action_id="b")).allowed
    decision = verifier.verify(grant, buy("15.00", action_id="c"))
    assert not decision.allowed
    assert decision.code == "over_budget"
    assert "$2.00 left" in decision.reason


def test_replayed_action_id_does_not_spend_twice(granted, verifier, store):
    """A retried request is not a second purchase."""
    grant = granted()
    first = verifier.verify(grant, buy("28.00", action_id="same"))
    second = verifier.verify(grant, buy("28.00", action_id="same"))
    assert first.allowed and second.allowed
    assert second.replayed
    allowed = [r for r in store.redemptions_for(grant["token_id"]) if r["allowed"]]
    assert len(allowed) == 1


def test_action_without_action_id_rejected(granted, verifier):
    action = buy("18.00")
    del action["action_id"]
    decision = verifier.verify(granted(), action)
    assert not decision.allowed
    assert decision.code == "malformed_action"


def test_concurrent_redemptions_cannot_overrun_max_uses(granted, verifier):
    """The time-of-check/time-of-use bug, tested for directly.

    Twenty threads race to redeem a max_uses:3 grant. If the usage check and the
    write were separate statements, several would each read "2 used" and proceed.
    """
    from concurrent.futures import ThreadPoolExecutor

    grant = granted()
    with ThreadPoolExecutor(max_workers=20) as pool:
        decisions = list(
            pool.map(
                lambda i: verifier.verify(grant, buy("1.00", action_id=f"race-{i}")),
                range(20),
            )
        )
    assert sum(1 for d in decisions if d.allowed) == 3
    assert all(d.code == "uses_exhausted" for d in decisions if not d.allowed)


def test_concurrent_redemptions_cannot_overrun_the_budget(granted, verifier):
    """Same race, against the cumulative $50 budget rather than the use count."""
    from concurrent.futures import ThreadPoolExecutor

    scope = {
        "action_type": "purchase",
        "constraints": {
            "merchant_allowlist": ["demo-bookstore.com"],
            "max_single_transaction_usd": 30,
            "max_amount_usd": 50,
            "max_uses": 100,
        },
    }
    grant = granted(scope)
    with ThreadPoolExecutor(max_workers=20) as pool:
        decisions = list(
            pool.map(
                lambda i: verifier.verify(grant, buy("30.00", action_id=f"race-{i}")),
                range(20),
            )
        )
    # $30 each against a $50 budget: exactly one fits, the rest must be refused.
    assert sum(1 for d in decisions if d.allowed) == 1


def test_dry_run_does_not_consume_a_use(granted, verifier, store):
    grant = granted()
    assert verifier.verify(grant, buy("18.00", action_id="p"), dry_run=True).allowed
    assert store.redemptions_for(grant["token_id"]) == []


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #


def test_revocation_denies_immediately(granted, verifier, consent):
    grant = granted()
    assert verifier.verify(grant, buy("18.00", action_id="a")).allowed
    consent.revoke(grant["token_id"], reason="changed my mind")
    decision = verifier.verify(grant, buy("18.00", action_id="b"))
    assert not decision.allowed
    assert decision.code == "revoked"
    assert "you revoked this permission" in decision.reason


def test_expired_grant_denied(consent, verifier, store):
    request = consent.request_scope(
        requested_by="agent:consent-agent-7f3a",
        purpose="buy a book",
        scope=PURCHASE_SCOPE,
        ttl_seconds=60,
    )
    grant = consent.approve(request["request_id"])
    # Re-mint with an expiry in the past, signed properly, to test the clock check
    # rather than the signature check.
    body = {k: v for k, v in grant.items() if k != "signature"}
    body["expires_at"] = to_iso(from_iso(body["issued_at"]) - timedelta(seconds=1))
    expired = {**body, "signature": consent.keyring.sign_grant(body)}
    decision = verifier.verify(expired, buy("18.00"))
    assert not decision.allowed
    assert decision.code == "expired"


def test_forged_token_id_unknown_to_issuer_denied(granted, verifier, consent):
    """Fail closed: 'never heard of it' is not 'not revoked'."""
    grant = copy.deepcopy(granted())
    body = {k: v for k, v in grant.items() if k != "signature"}
    body["token_id"] = "tok_neverissued"
    forged = {**body, "signature": consent.keyring.sign_grant(body)}
    decision = verifier.verify(forged, buy("18.00"))
    assert not decision.allowed
    assert decision.code == "unknown_token"


def test_unreachable_revocation_service_fails_closed(granted, keyring, store):
    class Broken:
        def status(self, token_id):
            raise ConnectionError("revocation service down")

    v = Verifier("demo-bookstore.com", keyring, Broken(), store=store)
    decision = v.verify(granted(), buy("18.00"))
    assert not decision.allowed
    assert decision.code == "revocation_unavailable"


# --------------------------------------------------------------------------- #
# forward compatibility is a security property
# --------------------------------------------------------------------------- #


def test_unknown_constraint_denies_rather_than_ignoring(granted, verifier, consent):
    """An older verifier meeting a newer restriction must refuse.

    Constraints only ever narrow permission, so silently ignoring one always
    widens it -- and the merchant would still look like it verified successfully.
    """
    grant = copy.deepcopy(granted())
    body = {k: v for k, v in grant.items() if k != "signature"}
    body["scope"]["constraints"]["max_items_per_order"] = 2  # from a future SDL
    unknown = {**body, "signature": consent.keyring.sign_grant(body)}
    decision = verifier.verify(unknown, buy("18.00"))
    assert not decision.allowed
    assert decision.code == "unknown_constraint"
    assert "max_items_per_order" in decision.reason


def test_version_mismatch_denied(granted, verifier, consent):
    grant = copy.deepcopy(granted())
    body = {k: v for k, v in grant.items() if k != "signature"}
    body["version"] = "sdl/2"
    future = {**body, "signature": consent.keyring.sign_grant(body)}
    decision = verifier.verify(future, buy("18.00"))
    assert not decision.allowed
    assert decision.code == "unsupported_version"


def test_garbage_input_denied_not_crashed(verifier):
    for junk in [None, "not-a-grant", 42, {}, {"token_id": "x"}]:
        decision = verifier.verify(junk, buy("18.00"))
        assert not decision.allowed


# --------------------------------------------------------------------------- #
# minting cannot widen
# --------------------------------------------------------------------------- #


def test_ttl_is_clamped_to_the_policy_ceiling(consent):
    from consent_layer.consent import MAX_TTL_SECONDS

    with pytest.raises(Exception):
        # The API layer bounds this too, but the service must not rely on that.
        consent.request_scope(
            requested_by="agent:x", purpose="", scope=PURCHASE_SCOPE, ttl_seconds=0
        )
    request = consent.request_scope(
        requested_by="agent:x",
        purpose="",
        scope=PURCHASE_SCOPE,
        ttl_seconds=MAX_TTL_SECONDS * 10,
    )
    grant = consent.approve(request["request_id"])
    lifetime = from_iso(grant["expires_at"]) - from_iso(grant["issued_at"])
    assert lifetime.total_seconds() <= MAX_TTL_SECONDS


def test_inexpressible_scope_never_becomes_a_request(consent):
    with pytest.raises(ScopeError):
        consent.request_scope(
            requested_by="agent:x",
            purpose="",
            scope={"action_type": "purchase", "constraints": {"max_uses": 1}},
        )


def test_a_request_can_only_be_decided_once(consent):
    request = consent.request_scope(
        requested_by="agent:x", purpose="", scope=PURCHASE_SCOPE
    )
    consent.approve(request["request_id"])
    with pytest.raises(ValueError):
        consent.approve(request["request_id"])
    with pytest.raises(ValueError):
        consent.deny(request["request_id"])
