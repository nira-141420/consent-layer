from __future__ import annotations

import os
from pathlib import Path

import pytest

from consent_layer.consent import ConsentLayer
from consent_layer.crypto import Keyring
from consent_layer.db import Store
from consent_layer.verifier import LocalRevocationSource, Verifier

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


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


@pytest.fixture
def keyring() -> Keyring:
    # Fixed seed: deterministic tests, and signatures are still real Ed25519.
    return Keyring(b"\x01" * 32, "user:priya@domain.com#key1")


@pytest.fixture
def consent(store: Store, keyring: Keyring) -> ConsentLayer:
    return ConsentLayer(store=store, keyring=keyring)


@pytest.fixture
def verifier(store: Store, keyring: Keyring) -> Verifier:
    return Verifier(
        "demo-bookstore.com", keyring, LocalRevocationSource(store), store=store
    )


@pytest.fixture
def granted(consent: ConsentLayer):
    """A fully approved grant for the standard purchase scope."""

    def _make(scope=None, ttl_seconds=86400):
        request = consent.request_scope(
            requested_by="agent:consent-agent-7f3a",
            purpose="buy the book you asked about",
            scope=scope or PURCHASE_SCOPE,
            ttl_seconds=ttl_seconds,
        )
        return consent.approve(request["request_id"], note="ok")

    return _make


def buy(amount: str, *, action_id: str = "act_1", **overrides) -> dict:
    action = {
        "action_id": action_id,
        "type": "purchase",
        "merchant": "demo-bookstore.com",
        "category": "books",
        "amount_usd": amount,
        "currency": "USD",
    }
    action.update(overrides)
    return action


@pytest.fixture
def api(tmp_path: Path):
    from fastapi.testclient import TestClient

    from consent_layer.app import build_app

    client = TestClient(build_app(tmp_path / "api"))
    yield client
    client.app.state.store.close()
