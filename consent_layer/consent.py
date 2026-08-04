"""The consent layer proper: turn a human "yes" into a signed, narrow grant.

The invariant this module exists to hold: **a grant can only ever be narrower than
what was requested.** Approval mints a token from the *stored* request, never from
anything the agent re-sends at approval time, and the TTL is clamped to the policy
ceiling. There is no code path where approving widens a scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Any

from .crypto import Keyring
from .db import Store, from_iso, new_id, now, to_iso
from .sdl import (
    SDL_VERSION,
    ScopeError,
    fmt_money,
    money,
    render_clauses,
    render_expiry,
    render_summary,
    validate_scope,
)

#: No grant may outlive this, whatever the agent asks for. A permission that never
#: expires is the thing this project exists to avoid.
MAX_TTL_SECONDS = 7 * 24 * 3600
DEFAULT_TTL_SECONDS = 24 * 3600


@dataclass
class ConsentLayer:
    store: Store
    keyring: Keyring
    issuer: str = "user:priya@domain.com"

    # -- requests ------------------------------------------------------------

    def request_scope(
        self,
        *,
        requested_by: str,
        purpose: str,
        scope: dict[str, Any],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> dict[str, Any]:
        """An agent asks for permission. Rejected here if it is not expressible."""
        validate_scope(scope)  # raises ScopeError
        if not isinstance(ttl_seconds, int) or ttl_seconds < 60:
            raise ScopeError("ttl_seconds must be a whole number of at least 60")
        ttl = min(ttl_seconds, MAX_TTL_SECONDS)

        request = self.store.create_request(
            requested_by=requested_by,
            purpose=purpose,
            scope=scope,
            ttl_seconds=ttl,
        )
        return self.decorate_request(request)

    def decorate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Attach the plain-language rendering the consent screen shows."""
        return {
            **request,
            "summary": render_summary(
                {"scope": request["scope"], "issued_to": request["requested_by"]}
            ),
            "clauses": render_clauses(request["scope"]),
            "duration": _duration_phrase(request["ttl_seconds"]),
        }

    # -- decisions -----------------------------------------------------------

    def approve(
        self, request_id: str, *, note: str = "", actor: str | None = None
    ) -> dict[str, Any]:
        request = self.store.get_request(request_id)
        if request is None:
            raise KeyError(request_id)
        if request["status"] != "pending":
            raise ValueError(f"request already {request['status']}")

        grant = self._mint(request)
        self.store.decide_request(
            request_id,
            approved=True,
            note=note,
            actor=actor or self.issuer,
            grant=grant,
        )
        return grant

    def deny(
        self, request_id: str, *, note: str = "", actor: str | None = None
    ) -> None:
        self.store.decide_request(
            request_id, approved=False, note=note, actor=actor or self.issuer
        )

    def revoke(
        self, token_id: str, *, reason: str = "revoked by user", actor: str | None = None
    ) -> dict[str, Any]:
        return self.store.revoke(token_id, reason=reason, actor=actor or self.issuer)

    # -- minting -------------------------------------------------------------

    def _mint(self, request: dict[str, Any]) -> dict[str, Any]:
        # Re-validate at mint time. The request passed validation when it was
        # stored, but the token is what gets signed, so it is what must be checked.
        validate_scope(request["scope"])

        issued = now()
        ttl = min(int(request["ttl_seconds"]), MAX_TTL_SECONDS)

        # Field order here is cosmetic -- signing runs through canonical_json,
        # which sorts keys -- but it keeps the raw token readable in the demo.
        body = {
            "token_id": new_id("tok"),
            "version": SDL_VERSION,
            "issuer": self.issuer,
            "issued_to": request["requested_by"],
            "issued_at": to_iso(issued),
            "expires_at": to_iso(issued + timedelta(seconds=ttl)),
            "scope": request["scope"],
            "revocable": True,
            "audit_required": True,
        }
        return {**body, "signature": self.keyring.sign_grant(body)}

    # -- read models for the UI ---------------------------------------------

    def grant_view(self, token_id: str) -> dict[str, Any] | None:
        record = self.store.get_grant(token_id)
        if record is None:
            return None
        grant = record["grant"]
        redemptions = self.store.redemptions_for(token_id)
        allowed = [r for r in redemptions if r["allowed"]]

        expired = now() >= from_iso(grant["expires_at"])
        if record["revoked_at"]:
            state = "revoked"
        elif expired:
            state = "expired"
        else:
            state = "active"

        return {
            **record,
            "state": state,
            "summary": render_summary(grant),
            "clauses": render_clauses(grant["scope"]),
            "expiry_phrase": render_expiry(grant["expires_at"]),
            "remaining": self._remaining(grant, allowed),
            "redemptions": redemptions,
        }

    def _remaining(
        self, grant: dict[str, Any], allowed: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """What is left of the grant -- shown on the UI as budget bars."""
        constraints = grant["scope"]["constraints"]
        out: list[dict[str, Any]] = []

        if "max_uses" in constraints:
            cap = int(constraints["max_uses"])
            used = len(allowed)
            out.append(
                {
                    "label": "Uses",
                    "used": used,
                    "limit": cap,
                    "display": f"{used} of {cap} used",
                    "fraction": min(1.0, used / cap) if cap else 1.0,
                }
            )

        if "max_amount_usd" in constraints:
            cap = money(constraints["max_amount_usd"])
            spent = Decimal(0)
            for redemption in allowed:
                value = redemption["action"].get("amount_usd")
                if value is not None:
                    try:
                        spent += money(value)
                    except Exception:
                        pass
            out.append(
                {
                    "label": "Budget",
                    "used": str(spent),
                    "limit": str(cap),
                    "display": f"{fmt_money(spent)} of {fmt_money(cap)} spent",
                    "fraction": float(min(Decimal(1), spent / cap)) if cap else 1.0,
                }
            )
        return out


def _duration_phrase(seconds: int) -> str:
    hours = seconds / 3600
    if hours < 1:
        return f"{int(seconds // 60)} minutes"
    if hours < 48:
        return f"{round(hours)} hours"
    return f"{round(hours / 24)} days"
