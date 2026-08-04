"""The Verification SDK.

This is the piece a merchant actually integrates, and the whole pitch rests on it
being small enough to adopt in an afternoon:

    verifier = Verifier("demo-bookstore.com", keyring, revocation)
    decision = verifier.verify(grant, {"action_id": ..., "type": "purchase", ...})
    if not decision.allowed:
        return 403, decision.reason

Two properties are worth being loud about.

**Fail closed.** Every exit that is not an explicit pass is a denial. An unknown
signature algorithm, an unknown constraint name, an unparseable timestamp, a
revocation service that cannot be reached -- all denials. The dangerous failure
mode for a permission system is not "denied something it should have allowed".

**Forward-compatibility is a security property.** If a grant carries a constraint
this verifier's registry does not contain, it must refuse. A newer consent layer
adding `max_recipients_per_day` must not be silently ignored by an older merchant
that would then honour every *other* restriction and look like it verified fine.
Constraints only ever narrow permission, so ignoring one always widens it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Protocol

from .crypto import Keyring
from .db import Store, from_iso, now
from .sdl import (
    ACTION_TYPES,
    CONSTRAINTS,
    SDL_VERSION,
    Denial,
    StaticUsage,
    UsageView,
)

REQUIRED_GRANT_FIELDS = (
    "token_id",
    "version",
    "issuer",
    "issued_to",
    "issued_at",
    "expires_at",
    "scope",
    "signature",
)


@dataclass
class Check:
    """One step of the algorithm, recorded so the demo can show the work."""

    step: int
    name: str
    passed: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass
class Decision:
    allowed: bool
    code: str
    reason: str
    token_id: str | None = None
    checks: list[Check] = field(default_factory=list)
    replayed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "code": self.code,
            "reason": self.reason,
            "token_id": self.token_id,
            "replayed": self.replayed,
            "checks": [c.as_dict() for c in self.checks],
        }


class RevocationSource(Protocol):
    """How a verifier asks "is this still live?".

    Deliberately a one-method interface: it is the only part of verification that
    needs a live callout, and therefore the only part that has to change for the
    offline/distributed story (short-lived grants, signed revocation lists,
    gossiped bloom filters). Everything else the token already carries.
    """

    def status(self, token_id: str) -> dict[str, Any]: ...


class LocalRevocationSource:
    """MVP: the merchant reads the issuer's database directly."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def status(self, token_id: str) -> dict[str, Any]:
        return self._store.revocation_status(token_id)


class Verifier:
    def __init__(
        self,
        name: str,
        keyring: Keyring,
        revocation: RevocationSource,
        store: Store | None = None,
    ) -> None:
        self.name = name
        self.keyring = keyring
        self.revocation = revocation
        # Without a store the verifier can still answer statelessly -- useful for
        # "would this be allowed?" previews that must not consume a use.
        self.store = store

    # -- public API ----------------------------------------------------------

    def verify(
        self, grant: Any, action: dict[str, Any], *, dry_run: bool = False
    ) -> Decision:
        checks: list[Check] = []
        moment = now()

        def fail(step: int, name: str, code: str, reason: str) -> Decision:
            checks.append(Check(step, name, False, reason))
            decision = Decision(False, code, reason, _token_id(grant), checks)
            if self.store is not None and not dry_run:
                self.store.record_rejection(
                    token_id=decision.token_id,
                    denial=Denial(code, reason),
                    action=action,
                    verifier=self.name,
                )
            return decision

        def passed(step: int, name: str, detail: str = "") -> None:
            checks.append(Check(step, name, True, detail))

        # -- 0. shape --------------------------------------------------------
        if not isinstance(grant, dict):
            return fail(0, "Grant is well-formed", "malformed", "grant is not an object")
        missing = [f for f in REQUIRED_GRANT_FIELDS if f not in grant]
        if missing:
            return fail(
                0, "Grant is well-formed", "malformed",
                f"grant is missing required field(s): {', '.join(missing)}",
            )
        if grant.get("version") != SDL_VERSION:
            return fail(
                0, "Grant is well-formed", "unsupported_version",
                f"this verifier speaks {SDL_VERSION}, the grant claims "
                f"{grant.get('version')!r}",
            )
        if not isinstance(action, dict) or not action.get("action_id"):
            return fail(
                0, "Grant is well-formed", "malformed_action",
                "the attempted action must carry an action_id so retries are not "
                "counted twice",
            )
        passed(0, "Grant is well-formed")

        # -- 1. signature ----------------------------------------------------
        ok, why = self.keyring.verify_grant(grant)
        if not ok:
            return fail(1, "Signature is valid", "bad_signature", why)
        passed(1, "Signature is valid", f"signed by {grant['signature']['key_id']}")

        # -- 2. validity window ----------------------------------------------
        try:
            issued_at = from_iso(grant["issued_at"])
            expires_at = from_iso(grant["expires_at"])
        except (ValueError, AttributeError, TypeError):
            return fail(2, "Still within its validity window", "malformed",
                        "grant timestamps are not valid ISO-8601")
        if moment < issued_at:
            return fail(2, "Still within its validity window", "not_yet_valid",
                        f"this permission does not start until {grant['issued_at']}")
        if moment >= expires_at:
            return fail(2, "Still within its validity window", "expired",
                        f"this permission expired at {grant['expires_at']}")
        passed(2, "Still within its validity window", f"valid until {grant['expires_at']}")

        # -- 3. revocation (the one live callout) ----------------------------
        try:
            status = self.revocation.status(grant["token_id"])
        except Exception as exc:  # network, DB, anything
            # Fail closed: an unreachable revocation service is not permission.
            return fail(3, "Not revoked", "revocation_unavailable",
                        f"could not confirm this permission is still live ({exc})")
        if not status.get("known", False):
            return fail(3, "Not revoked", "unknown_token",
                        "the issuer has no record of this permission")
        if status.get("revoked"):
            return fail(3, "Not revoked", "revoked",
                        "you revoked this permission"
                        + (f" at {status['revoked_at']}" if status.get("revoked_at") else ""))
        passed(3, "Not revoked")

        # -- 4. action type --------------------------------------------------
        scope = grant.get("scope")
        if not isinstance(scope, dict) or not isinstance(scope.get("constraints"), dict):
            return fail(4, "Action type matches the grant", "malformed",
                        "grant scope is malformed")
        granted_type = scope.get("action_type")
        if granted_type not in ACTION_TYPES:
            return fail(4, "Action type matches the grant", "unknown_action_type",
                        f"this verifier does not understand action type {granted_type!r}")
        if action.get("type") != granted_type:
            return fail(4, "Action type matches the grant", "action_type_mismatch",
                        f"this permission covers {granted_type!r}, but the agent "
                        f"attempted {action.get('type')!r}")
        passed(4, "Action type matches the grant", str(granted_type))

        # -- 5. every constraint is understood -------------------------------
        constraints: dict[str, Any] = scope["constraints"]
        unknown = sorted(set(constraints) - set(CONSTRAINTS))
        if unknown:
            return fail(
                5, "All restrictions are understood", "unknown_constraint",
                f"this permission carries restriction(s) this verifier cannot "
                f"enforce ({', '.join(unknown)}); refusing rather than ignoring them",
            )
        passed(5, "All restrictions are understood", f"{len(constraints)} restriction(s)")

        # -- 6. stateless constraints ----------------------------------------
        empty_usage = StaticUsage()
        for name, value in sorted(constraints.items()):
            primitive = CONSTRAINTS[name]
            if primitive.stateful:
                continue
            denial = primitive.check(value, action, empty_usage, moment)
            if denial:
                return fail(6, "Action fits what you approved", denial.code, denial.message)
        passed(6, "Action fits what you approved")

        # -- 7. usage limits, checked and consumed atomically ----------------
        stateful = {n: v for n, v in constraints.items() if CONSTRAINTS[n].stateful}

        def stateful_check(usage: UsageView) -> Denial | None:
            for name, value in sorted(stateful.items()):
                denial = CONSTRAINTS[name].check(value, action, usage, moment)
                if denial:
                    return denial
            return None

        if self.store is None or dry_run:
            # No ledger to consult (or explicitly asked not to spend a use).
            denial = stateful_check(StaticUsage())
            if denial:
                return fail(7, "Within its usage limits", denial.code, denial.message)
            passed(7, "Within its usage limits", "not checked against history (dry run)")
            return Decision(True, "allowed", "allowed (dry run)", grant["token_id"], checks)

        outcome = self.store.redeem(
            token_id=grant["token_id"],
            action_id=str(action["action_id"]),
            action=action,
            verifier=self.name,
            stateful_check=stateful_check,
        )
        if not outcome["allowed"]:
            checks.append(Check(7, "Within its usage limits", False, outcome["reason"] or ""))
            return Decision(
                False, outcome["code"] or "denied", outcome["reason"] or "denied",
                grant["token_id"], checks, replayed=outcome["replayed"],
            )
        passed(
            7,
            "Within its usage limits",
            "replay of an earlier decision" if outcome["replayed"] else "recorded",
        )
        return Decision(
            True, "allowed", "allowed", grant["token_id"], checks,
            replayed=outcome["replayed"],
        )


def _token_id(grant: Any) -> str | None:
    return grant.get("token_id") if isinstance(grant, dict) else None
