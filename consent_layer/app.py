"""HTTP surface: consent layer, demo merchant, audit viewer, and the UI.

The merchant lives in the same process as the consent layer purely so the demo is
one command. Architecturally it is a different party -- note that it only ever
touches `Verifier`, and reaches the issuer through the `RevocationSource`
interface. Nothing in `/merchant/*` imports the minting code.
"""

from __future__ import annotations

import os
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .consent import DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS, ConsentLayer
from .crypto import load_or_create_keyring
from .db import Store, new_id
from .sdl import (
    ScopeError,
    action_type_catalogue,
    money,
    render_clauses,
    render_summary,
    validate_scope,
)
from .verifier import LocalRevocationSource, Verifier

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("CONSENT_LAYER_DATA", ROOT / "data"))
UI_DIR = ROOT / "ui"

MERCHANT_DOMAIN = "demo-bookstore.com"

#: The merchant's own catalogue. Prices live *here*, not in the agent's request --
#: see the note in /merchant/purchase about why that matters.
CATALOG: list[dict[str, Any]] = [
    {"id": "bk-001", "title": "The Design of Everyday Things", "price_usd": "18.00", "category": "books"},
    {"id": "bk-002", "title": "Thinking in Systems", "price_usd": "22.50", "category": "books"},
    {"id": "bk-003", "title": "Seeing Like a State", "price_usd": "26.00", "category": "books"},
    {"id": "bk-004", "title": "The Complete Encyclopaedia of Cartography", "price_usd": "48.00", "category": "books"},
    {"id": "el-001", "title": "Noise-cancelling Headphones", "price_usd": "24.00", "category": "electronics"},
]


# Request models live at module scope on purpose: `from __future__ import
# annotations` turns every annotation into a string, and FastAPI resolves those
# against the *module* namespace. A model defined inside build_app() is invisible
# there, and FastAPI silently degrades it to a query parameter.


class ScopeRequest(BaseModel):
    requested_by: str = Field(..., description="agent identity, e.g. agent:consent-agent-7f3a")
    purpose: str = Field("", description="why the agent says it needs this")
    scope: dict[str, Any]
    ttl_seconds: int = Field(DEFAULT_TTL_SECONDS, ge=60, le=MAX_TTL_SECONDS)


class Decision(BaseModel):
    note: str = ""


class Revocation(BaseModel):
    reason: str = "revoked by user"


class Purchase(BaseModel):
    grant: dict[str, Any]
    item_id: str
    quantity: int = Field(1, ge=1, le=100)
    action_id: str | None = None


class ScopePreview(BaseModel):
    scope: dict[str, Any]


def build_app(data_dir: Path | None = None) -> FastAPI:
    data_dir = Path(data_dir or DATA_DIR)
    data_dir.mkdir(parents=True, exist_ok=True)

    store = Store(data_dir / "consent.db")
    keyring = load_or_create_keyring(data_dir / "issuer.key")
    consent = ConsentLayer(store=store, keyring=keyring)

    # The merchant's view of the world: it trusts the issuer's public key and can
    # ask about revocation. It cannot mint anything.
    merchant_keyring = load_or_create_keyring(data_dir / "issuer.key")
    verifier = Verifier(
        name=MERCHANT_DOMAIN,
        keyring=merchant_keyring,
        revocation=LocalRevocationSource(store),
        store=store,
    )

    app = FastAPI(
        title="Consent Layer for AI Agents",
        version="1.0",
        description="Narrow, revocable, auditable permissions for agent actions.",
    )
    app.state.store = store
    app.state.consent = consent
    app.state.verifier = verifier

    # ------------------------------------------------------------------ #
    # consent layer
    # ------------------------------------------------------------------ #

    @app.post("/api/requests", tags=["consent"])
    def create_request(body: ScopeRequest) -> dict[str, Any]:
        """An agent asks for a narrow permission. Nothing is granted yet."""
        try:
            return consent.request_scope(
                requested_by=body.requested_by,
                purpose=body.purpose,
                scope=body.scope,
                ttl_seconds=body.ttl_seconds,
            )
        except ScopeError as exc:
            raise HTTPException(422, f"scope is not expressible in SDL v1: {exc}")

    @app.get("/api/requests", tags=["consent"])
    def list_requests(status: str | None = None) -> list[dict[str, Any]]:
        return [consent.decorate_request(r) for r in store.list_requests(status)]

    @app.get("/api/requests/{request_id}", tags=["consent"])
    def get_request(request_id: str) -> dict[str, Any]:
        request = store.get_request(request_id)
        if request is None:
            raise HTTPException(404, "no such request")
        return consent.decorate_request(request)

    @app.post("/api/requests/{request_id}/approve", tags=["consent"])
    def approve(request_id: str, body: Decision) -> dict[str, Any]:
        """The human says yes. This is the only place a grant is ever minted."""
        try:
            grant = consent.approve(request_id, note=body.note)
        except KeyError:
            raise HTTPException(404, "no such request")
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"grant": grant, "view": consent.grant_view(grant["token_id"])}

    @app.post("/api/requests/{request_id}/deny", tags=["consent"])
    def deny(request_id: str, body: Decision) -> dict[str, str]:
        try:
            consent.deny(request_id, note=body.note)
        except KeyError:
            raise HTTPException(404, "no such request")
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {"status": "denied"}

    @app.get("/api/grants", tags=["consent"])
    def list_grants() -> list[dict[str, Any]]:
        return [consent.grant_view(g["token_id"]) for g in store.list_grants()]

    @app.get("/api/grants/{token_id}", tags=["consent"])
    def get_grant(token_id: str) -> dict[str, Any]:
        view = consent.grant_view(token_id)
        if view is None:
            raise HTTPException(404, "no such grant")
        return view

    @app.post("/api/grants/{token_id}/revoke", tags=["consent"])
    def revoke(token_id: str, body: Revocation) -> dict[str, Any]:
        try:
            return consent.revoke(token_id, reason=body.reason)
        except KeyError:
            raise HTTPException(404, "no such grant")

    @app.get("/api/revocations/{token_id}", tags=["consent"])
    def revocation_status(token_id: str) -> dict[str, Any]:
        """The one live callout a verifier makes. Everything else the token carries."""
        return store.revocation_status(token_id)

    @app.get("/api/vocabulary", tags=["consent"])
    def vocabulary() -> dict[str, Any]:
        return {"version": "sdl/1", "action_types": action_type_catalogue()}

    @app.post("/api/preview", tags=["consent"])
    def preview(body: ScopePreview) -> dict[str, Any]:
        """Render a scope as English without creating anything. Used by the UI."""
        try:
            validate_scope(body.scope)
        except ScopeError as exc:
            return {"valid": False, "error": str(exc), "clauses": []}
        return {
            "valid": True,
            "summary": render_summary({"scope": body.scope, "issued_to": "the agent"}),
            "clauses": render_clauses(body.scope),
        }

    @app.get("/api/public-key", tags=["consent"])
    def public_key() -> dict[str, str]:
        return {"key_id": keyring.key_id, "alg": "Ed25519",
                "public_key": keyring.public_key_b64}

    # ------------------------------------------------------------------ #
    # demo merchant -- consumes the Verify SDK, mints nothing
    # ------------------------------------------------------------------ #

    @app.get("/merchant/catalog", tags=["merchant"])
    def catalog() -> dict[str, Any]:
        return {"merchant": MERCHANT_DOMAIN, "items": CATALOG}

    @app.post("/merchant/purchase", tags=["merchant"])
    def purchase(body: Purchase) -> JSONResponse:
        """Attempt a purchase against a grant.

        Note where the numbers come from: the *merchant* looks up the price and
        fills in its own domain. The agent supplies only the item and an
        action_id. An agent that could assert its own `amount_usd` could
        under-report it and slide past the spending cap -- the constrained
        fields have to be filled in by the party that actually knows them.
        """
        item = next((i for i in CATALOG if i["id"] == body.item_id), None)
        if item is None:
            raise HTTPException(404, "no such item")

        amount = money(item["price_usd"]) * body.quantity
        action = {
            "action_id": body.action_id or new_id("act"),
            "type": "purchase",
            "merchant": MERCHANT_DOMAIN,
            "category": item["category"],
            "amount_usd": f"{amount:.2f}",
            "currency": "USD",
            "description": f"{body.quantity} x {item['title']}",
        }

        decision = verifier.verify(body.grant, action)
        payload: dict[str, Any] = {
            "decision": decision.as_dict(),
            "action": action,
            "item": item,
        }
        if decision.allowed:
            # Payments are mocked -- see the proposal's scope table.
            payload["receipt"] = {
                "merchant": MERCHANT_DOMAIN,
                "charged": f"would have charged ${amount:.2f}",
                "description": action["description"],
            }
            return JSONResponse(payload, status_code=200)
        return JSONResponse(payload, status_code=403)

    @app.post("/merchant/preview", tags=["merchant"])
    def preview_purchase(body: Purchase) -> dict[str, Any]:
        """Would this be allowed? Runs the same checks but consumes nothing."""
        item = next((i for i in CATALOG if i["id"] == body.item_id), None)
        if item is None:
            raise HTTPException(404, "no such item")
        amount = money(item["price_usd"]) * body.quantity
        action = {
            "action_id": "preview",
            "type": "purchase",
            "merchant": MERCHANT_DOMAIN,
            "category": item["category"],
            "amount_usd": f"{amount:.2f}",
            "currency": "USD",
        }
        return {"decision": verifier.verify(body.grant, action, dry_run=True).as_dict()}

    # ------------------------------------------------------------------ #
    # audit
    # ------------------------------------------------------------------ #

    @app.get("/api/audit", tags=["audit"])
    def audit_log(limit: int = 200) -> dict[str, Any]:
        return {
            "entries": store.audit_entries(limit),
            "chain": store.verify_audit_chain(),
        }

    @app.get("/api/audit/verify", tags=["audit"])
    def audit_verify() -> dict[str, Any]:
        return store.verify_audit_chain()

    @app.post("/api/demo/tamper/{seq}", tags=["demo"])
    def tamper(seq: int) -> dict[str, Any]:
        """DEMO ONLY. Edits a historic audit row behind the log's back so the
        chain check can be shown catching it."""
        if not store.tamper_with_audit_row(seq):
            raise HTTPException(404, "no such audit entry")
        return {"tampered_seq": seq, "chain": store.verify_audit_chain()}

    @app.post("/api/demo/reset", tags=["demo"])
    def reset() -> dict[str, str]:
        store.reset()
        return {"status": "reset"}

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    if UI_DIR.exists():
        app.mount("/static", StaticFiles(directory=UI_DIR), name="static")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(UI_DIR / "index.html")

    return app


app = build_app()
