"""Tests for the Scope Definition Language itself."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from consent_layer.canonical import CanonicalizationError, canonical_json
from consent_layer.sdl import (
    ACTION_TYPES,
    CONSTRAINTS,
    ScopeError,
    StaticUsage,
    render_clauses,
    render_summary,
    validate_scope,
)

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)

PURCHASE_SCOPE = {
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


# --------------------------------------------------------------------------- #
# design principles, enforced mechanically
# --------------------------------------------------------------------------- #


def test_every_constraint_is_human_renderable():
    """The "human-renderable or it doesn't belong in v1" principle, as a test.

    A constraint that cannot be turned into an English clause cannot be consented
    to, so the registry must never contain one.
    """
    samples = {
        "merchant_allowlist": ["a.com", "b.com"],
        "category": ["books"],
        "max_single_transaction_usd": 30,
        "max_amount_usd": 50,
        "currency": "USD",
        "recipient_allowlist": ["a@b.com"],
        "channel": "email",
        "resource_allowlist": ["/tmp/notes.md"],
        "allowed_operations": ["read", "write"],
        "max_size_bytes": 1024,
        "endpoint_allowlist": ["https://api.example.com/v1/items"],
        "method_allowlist": ["GET"],
        "max_uses": 3,
        "rate_limit_per_hour": 5,
        "rate_limit_per_day": 20,
    }
    assert set(samples) == set(CONSTRAINTS), "every constraint needs a sample here"
    for name, value in samples.items():
        clause = CONSTRAINTS[name].render(value)
        assert isinstance(clause, str) and clause.strip(), name


def test_every_action_type_constraint_exists_in_the_registry():
    for action in ACTION_TYPES.values():
        assert action.allowed <= set(CONSTRAINTS), action.name
        assert action.required <= action.allowed, action.name


def test_all_four_action_types_validate():
    scopes = [
        PURCHASE_SCOPE,
        {
            "action_type": "send_message",
            "constraints": {"recipient_allowlist": ["ops@acme.com"], "channel": "email"},
        },
        {
            "action_type": "edit_resource",
            "constraints": {
                "resource_allowlist": ["/notes/todo.md"],
                "allowed_operations": ["read", "write"],
            },
        },
        {
            "action_type": "api_call",
            "constraints": {
                "endpoint_allowlist": ["https://api.example.com/v1/items"],
                "method_allowlist": ["GET"],
                "rate_limit_per_hour": 10,
            },
        },
    ]
    for scope in scopes:
        action, constraints = validate_scope(scope)
        assert action.name == scope["action_type"]
        assert constraints


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def test_unknown_action_type_rejected():
    with pytest.raises(ScopeError, match="unknown action_type"):
        validate_scope({"action_type": "launch_missiles", "constraints": {"max_uses": 1}})


def test_unknown_constraint_rejected_at_mint_time():
    with pytest.raises(ScopeError, match="unknown constraint"):
        validate_scope(
            {
                "action_type": "purchase",
                "constraints": {**PURCHASE_SCOPE["constraints"], "vibes": "good"},
            }
        )


def test_constraint_from_another_action_type_rejected():
    with pytest.raises(ScopeError, match="do not apply"):
        validate_scope(
            {
                "action_type": "purchase",
                "constraints": {
                    **PURCHASE_SCOPE["constraints"],
                    "recipient_allowlist": ["a@b.com"],
                },
            }
        )


def test_purchase_without_merchant_allowlist_is_not_expressible():
    """A spend permission with no merchant list is a blank cheque."""
    with pytest.raises(ScopeError, match="merchant_allowlist"):
        validate_scope(
            {
                "action_type": "purchase",
                "constraints": {"max_single_transaction_usd": 30},
            }
        )


def test_per_transaction_cap_above_budget_rejected():
    with pytest.raises(ScopeError, match="cannot exceed"):
        validate_scope(
            {
                "action_type": "purchase",
                "constraints": {
                    "merchant_allowlist": ["a.com"],
                    "max_single_transaction_usd": 100,
                    "max_amount_usd": 50,
                },
            }
        )


def test_float_amounts_rejected():
    with pytest.raises(ScopeError, match="float"):
        validate_scope(
            {
                "action_type": "purchase",
                "constraints": {
                    "merchant_allowlist": ["a.com"],
                    "max_single_transaction_usd": 29.99,
                },
            }
        )


def test_decimal_string_amounts_accepted():
    validate_scope(
        {
            "action_type": "purchase",
            "constraints": {
                "merchant_allowlist": ["a.com"],
                "max_single_transaction_usd": "29.99",
            },
        }
    )


def test_empty_allowlist_rejected():
    with pytest.raises(ScopeError):
        validate_scope(
            {
                "action_type": "purchase",
                "constraints": {
                    "merchant_allowlist": [],
                    "max_single_transaction_usd": 30,
                },
            }
        )


# --------------------------------------------------------------------------- #
# constraint behaviour
# --------------------------------------------------------------------------- #


def test_allowlist_denies_and_explains():
    denial = CONSTRAINTS["merchant_allowlist"].check(
        ["demo-bookstore.com"], {"merchant": "sketchy.example"}, StaticUsage(), NOW
    )
    assert denial and denial.code == "not_in_allowlist"
    assert "sketchy.example" in denial.message


def test_plain_language_pluralises_properly():
    """"categorys" reads as a bug in a screen whose whole job is to be trusted."""
    denial = CONSTRAINTS["category"].check(
        ["books"], {"category": "electronics"}, StaticUsage(), NOW
    )
    assert "approved categories" in denial.message
    assert CONSTRAINTS["category"].render(["books", "music"]).startswith(
        "only these categories:"
    )


def test_allowlist_normalises_domains():
    """https://www.Demo-Bookstore.com/checkout is the same merchant."""
    assert (
        CONSTRAINTS["merchant_allowlist"].check(
            ["demo-bookstore.com"],
            {"merchant": "https://www.Demo-Bookstore.com/checkout"},
            StaticUsage(),
            NOW,
        )
        is None
    )


def test_missing_action_field_is_a_denial_not_a_pass():
    """Deny by default: a field the verifier cannot see is not a field that passes."""
    denial = CONSTRAINTS["merchant_allowlist"].check(
        ["demo-bookstore.com"], {}, StaticUsage(), NOW
    )
    assert denial and denial.code == "action_field_missing"


def test_cumulative_budget_counts_prior_spend():
    from decimal import Decimal

    usage = StaticUsage(count=1, totals={"amount_usd": Decimal("40.00")})
    denial = CONSTRAINTS["max_amount_usd"].check(50, {"amount_usd": "15.00"}, usage, NOW)
    assert denial and denial.code == "over_budget"
    assert "$10.00 left" in denial.message


def test_rate_limit_counts_only_the_window():
    usage = StaticUsage(
        count=3,
        recent=[NOW - timedelta(minutes=10), NOW - timedelta(hours=5), NOW - timedelta(hours=9)],
    )
    assert CONSTRAINTS["rate_limit_per_hour"].check(2, {}, usage, NOW) is None
    assert CONSTRAINTS["rate_limit_per_hour"].check(1, {}, usage, NOW) is not None
    assert CONSTRAINTS["rate_limit_per_day"].check(3, {}, usage, NOW) is not None


# --------------------------------------------------------------------------- #
# plain language
# --------------------------------------------------------------------------- #


def test_summary_reads_like_a_sentence():
    summary = render_summary({"scope": PURCHASE_SCOPE, "issued_to": "agent:consent-agent-7f3a"})
    assert summary.startswith("Let agent:consent-agent-7f3a spend your money")
    assert "only merchant demo-bookstore.com" in summary
    assert "$30.00 in any one action" in summary
    assert "at most 3 times" in summary
    assert summary.endswith(".")


def test_clauses_are_in_reading_order_not_json_order():
    scrambled = {
        "action_type": "purchase",
        "constraints": {
            "max_uses": 3,
            "currency": "USD",
            "merchant_allowlist": ["demo-bookstore.com"],
            "max_single_transaction_usd": 30,
        },
    }
    clauses = render_clauses(scrambled)
    assert clauses[0].startswith("only merchant")
    assert clauses[-1] == "at most 3 times"


def test_unrenderable_constraint_is_surfaced_not_dropped():
    """If the UI cannot explain a clause it must say so, not hide it."""
    clauses = render_clauses({"constraints": {"future_thing": 1}})
    assert "cannot be shown" in clauses[0]


# --------------------------------------------------------------------------- #
# canonical serialization
# --------------------------------------------------------------------------- #


def test_canonical_json_is_key_order_independent():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_canonical_json_rejects_floats():
    with pytest.raises(CanonicalizationError):
        canonical_json({"amount": 29.99})
