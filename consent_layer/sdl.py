"""Scope Definition Language (SDL) v1.

The design goal is a *small set of composable primitives*, not a giant enum of
specific permissions. Concretely:

  * a **constraint primitive** knows how to do exactly three things -- validate its
    own value, check an attempted action against it, and render itself as an
    English sentence.
  * a **constraint** is a named binding of a primitive to a field of the action
    (`max_single_transaction_usd` = MaxPerAction bound to the action's `amount_usd`).
  * an **action type** is just a declaration of which constraint names are legal
    and which are mandatory.

Adding a new permission is therefore one row in `CONSTRAINTS` and one row in
`ACTION_TYPES`, not new verifier code. That is what "extensible vocabulary" has to
mean if it is going to mean anything.

Two properties are enforced mechanically rather than by convention:

  1. **Human-renderable.** A primitive cannot be registered without a renderer, so
     no field can enter the language unless it can be explained to the person
     approving it. (`tests/test_sdl.py` asserts this over the whole registry.)
  2. **Deny by default.** A constraint name the verifier does not recognise is a
     *denial*, never a shrug. An old verifier meeting a token from a newer issuer
     must refuse it rather than silently ignore the restriction it cannot enforce.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, ClassVar, Protocol

SDL_VERSION = "sdl/1"


# --------------------------------------------------------------------------- #
# money
# --------------------------------------------------------------------------- #
# Amounts cross the wire as ints (50) or decimal strings ("12.99"), never floats.
# canonical.py rejects floats outright, because float formatting is not stable
# enough to sign over and 0.1 + 0.2 is not a joke you want inside a spending cap.


class MoneyError(ValueError):
    pass


def money(value: Any, *, what: str = "amount") -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise MoneyError(f"{what} must be an integer or decimal string, not a float")
    if isinstance(value, int):
        amount = Decimal(value)
    elif isinstance(value, str):
        if not re.fullmatch(r"-?\d+(\.\d{1,2})?", value.strip()):
            raise MoneyError(f"{what} {value!r} is not a valid 2-decimal amount")
        try:
            amount = Decimal(value.strip())
        except InvalidOperation as exc:  # pragma: no cover - regex already guards
            raise MoneyError(f"{what} {value!r} is not a number") from exc
    else:
        raise MoneyError(f"{what} must be an integer or decimal string")
    if amount < 0:
        raise MoneyError(f"{what} may not be negative")
    return amount


def fmt_money(amount: Decimal) -> str:
    return f"${amount:,.2f}"


# --------------------------------------------------------------------------- #
# usage context
# --------------------------------------------------------------------------- #


class UsageView(Protocol):
    """What a verifier can learn about a grant's history.

    Kept deliberately narrow: these three questions are the entire stateful
    surface of verification, which is what makes offline/cached verification a
    tractable future step rather than a rewrite.
    """

    def use_count(self) -> int: ...

    def total_of(self, field_name: str) -> Decimal: ...

    def uses_since(self, since: datetime) -> int: ...


@dataclass
class StaticUsage:
    """A UsageView backed by plain values -- used in tests and for dry runs."""

    count: int = 0
    totals: dict[str, Decimal] = field(default_factory=dict)
    recent: list[datetime] = field(default_factory=list)

    def use_count(self) -> int:
        return self.count

    def total_of(self, field_name: str) -> Decimal:
        return self.totals.get(field_name, Decimal(0))

    def uses_since(self, since: datetime) -> int:
        return sum(1 for ts in self.recent if ts >= since)


# --------------------------------------------------------------------------- #
# constraint primitives
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Denial:
    """Why an action was refused: a stable machine code plus a human sentence."""

    code: str
    message: str


class Constraint:
    """Base class. Subclasses implement validate/check/render.

    Subclasses that read a field of the attempted action declare it as their own
    `field_name` attribute. It is deliberately *not* declared here with a default:
    a class-level default on a non-dataclass base leaks into every dataclass
    subclass as an implicit field default, which reorders their __init__ args.
    """

    #: True if `check` consults usage history. Stateful constraints must be
    #: evaluated inside the redemption transaction (see db.Store.redeem);
    #: stateless ones can be checked by anyone holding just the token.
    stateful: ClassVar[bool] = False

    def validate(self, value: Any) -> None:
        """Raise ValueError if `value` is not a legal setting for this constraint."""
        raise NotImplementedError

    def check(
        self, value: Any, action: dict[str, Any], usage: UsageView, now: datetime
    ) -> Denial | None:
        raise NotImplementedError

    def render(self, value: Any) -> str:
        """One English clause describing the restriction. Required -- see module docstring."""
        raise NotImplementedError

    # helper: pull the action field this constraint reads, or report it missing
    def _read(self, action: dict[str, Any]) -> tuple[Any, Denial | None]:
        assert self.field_name is not None
        if self.field_name not in action:
            return None, Denial(
                "action_field_missing",
                f"the action did not say what its {self.field_name.replace('_', ' ')} was",
            )
        return action[self.field_name], None


@dataclass(frozen=True)
class Allowlist(Constraint):
    """Action field must be one of an explicit set. Deny-by-default made concrete."""

    field_name: str
    noun: str
    match: str = "exact"  # "exact" | "casefold" | "domain"
    plural: str | None = None  # set where "add an s" gets it wrong

    @property
    def nouns(self) -> str:
        return self.plural or f"{self.noun}s"

    def validate(self, value: Any) -> None:
        if not isinstance(value, list) or not value:
            raise ValueError(f"{self.noun} allowlist must be a non-empty list")
        if not all(isinstance(v, str) and v.strip() for v in value):
            raise ValueError(f"{self.noun} allowlist entries must be non-empty strings")

    def _norm(self, raw: str) -> str:
        text = raw.strip()
        if self.match in ("casefold", "domain"):
            text = text.casefold()
        if self.match == "domain":
            text = re.sub(r"^https?://", "", text).split("/")[0].removeprefix("www.")
        return text

    def check(
        self, value: Any, action: dict[str, Any], usage: UsageView, now: datetime
    ) -> Denial | None:
        actual, missing = self._read(action)
        if missing:
            return missing
        if not isinstance(actual, str):
            return Denial("action_field_type", f"{self.noun} must be text")
        if self._norm(actual) not in {self._norm(v) for v in value}:
            return Denial(
                "not_in_allowlist",
                f"{self.noun} {actual!r} is not one of the approved "
                f"{self.nouns} ({', '.join(value)})",
            )
        return None

    def render(self, value: Any) -> str:
        items = list(value)
        if len(items) == 1:
            return f"only {self.noun} {items[0]}"
        return f"only these {self.nouns}: {', '.join(items)}"


@dataclass(frozen=True)
class MaxPerAction(Constraint):
    """Cap on a single action's amount."""

    field_name: str
    noun: str
    is_money: bool = True

    def validate(self, value: Any) -> None:
        if self.is_money:
            money(value, what=self.noun)
        else:
            _positive_int(value, self.noun)

    def check(
        self, value: Any, action: dict[str, Any], usage: UsageView, now: datetime
    ) -> Denial | None:
        actual, missing = self._read(action)
        if missing:
            return missing
        try:
            got = money(actual, what=self.noun) if self.is_money else _positive_int(actual, self.noun)
        except (MoneyError, ValueError) as exc:
            return Denial("action_field_type", str(exc))
        cap = money(value) if self.is_money else int(value)
        if got > cap:
            shown, capped = (
                (fmt_money(got), fmt_money(cap)) if self.is_money else (str(got), str(cap))
            )
            return Denial(
                "over_per_action_limit",
                f"{shown} is over the {capped} limit approved for a single action",
            )
        return None

    def render(self, value: Any) -> str:
        shown = fmt_money(money(value)) if self.is_money else str(value)
        return f"at most {shown} in any one action"


@dataclass(frozen=True)
class MaxCumulative(Constraint):
    """Budget: the running total across every use of this grant."""

    field_name: str
    noun: str

    stateful: ClassVar[bool] = True

    def validate(self, value: Any) -> None:
        money(value, what=self.noun)

    def check(
        self, value: Any, action: dict[str, Any], usage: UsageView, now: datetime
    ) -> Denial | None:
        actual, missing = self._read(action)
        if missing:
            return missing
        try:
            got = money(actual, what=self.noun)
        except MoneyError as exc:
            return Denial("action_field_type", str(exc))
        budget = money(value)
        spent = usage.total_of(self.field_name)
        if spent + got > budget:
            return Denial(
                "over_budget",
                f"{fmt_money(got)} would take the total to "
                f"{fmt_money(spent + got)}, over the {fmt_money(budget)} approved "
                f"({fmt_money(budget - spent)} left)",
            )
        return None

    def render(self, value: Any) -> str:
        return f"{fmt_money(money(value))} in total across all uses"


@dataclass(frozen=True)
class MaxUses(Constraint):
    """How many times the grant may be redeemed at all."""

    stateful: ClassVar[bool] = True

    def validate(self, value: Any) -> None:
        _positive_int(value, "max_uses")

    def check(
        self, value: Any, action: dict[str, Any], usage: UsageView, now: datetime
    ) -> Denial | None:
        used = usage.use_count()
        if used >= int(value):
            return Denial(
                "uses_exhausted",
                f"this permission was approved for {value} use(s) and has already "
                f"been used {used} time(s)",
            )
        return None

    def render(self, value: Any) -> str:
        n = int(value)
        return "once only" if n == 1 else f"at most {n} times"


@dataclass(frozen=True)
class RateLimit(Constraint):
    """At most N uses in a rolling window."""

    window_seconds: int
    window_label: str

    stateful: ClassVar[bool] = True

    def validate(self, value: Any) -> None:
        _positive_int(value, "rate limit")

    def check(
        self, value: Any, action: dict[str, Any], usage: UsageView, now: datetime
    ) -> Denial | None:
        window_start = now - timedelta(seconds=self.window_seconds)
        recent = usage.uses_since(window_start)
        if recent >= int(value):
            return Denial(
                "rate_limited",
                f"this permission allows {value} use(s) per {self.window_label} "
                f"and has already been used {recent} time(s) in that window",
            )
        return None

    def render(self, value: Any) -> str:
        return f"no more than {int(value)} time(s) per {self.window_label}"


@dataclass(frozen=True)
class Equals(Constraint):
    """Action field must match exactly."""

    field_name: str
    noun: str

    def validate(self, value: Any) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{self.noun} must be a non-empty string")

    def check(
        self, value: Any, action: dict[str, Any], usage: UsageView, now: datetime
    ) -> Denial | None:
        actual, missing = self._read(action)
        if missing:
            return missing
        if actual != value:
            return Denial(
                "value_mismatch",
                f"{self.noun} must be {value}, but the action used {actual}",
            )
        return None

    def render(self, value: Any) -> str:
        return f"{self.noun} {value}"


def _positive_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{what} must be a positive whole number")
    return value


# --------------------------------------------------------------------------- #
# the vocabulary
# --------------------------------------------------------------------------- #

CONSTRAINTS: dict[str, Constraint] = {
    # purchase
    "merchant_allowlist": Allowlist("merchant", "merchant", match="domain"),
    "category": Allowlist("category", "category", match="casefold", plural="categories"),
    "max_single_transaction_usd": MaxPerAction("amount_usd", "amount"),
    "max_amount_usd": MaxCumulative("amount_usd", "amount"),
    "currency": Equals("currency", "currency"),
    # send_message
    "recipient_allowlist": Allowlist("recipient", "recipient", match="casefold"),
    "channel": Equals("channel", "channel"),
    # edit_resource
    "resource_allowlist": Allowlist(
        "resource_id", "resource", match="casefold", plural="resources"
    ),
    "allowed_operations": Allowlist("operation", "operation", match="casefold"),
    "max_size_bytes": MaxPerAction("size_bytes", "size", is_money=False),
    # api_call
    "endpoint_allowlist": Allowlist("endpoint", "endpoint", match="casefold"),
    "method_allowlist": Allowlist("method", "method", match="casefold"),
    # universal
    "max_uses": MaxUses(),
    "rate_limit_per_hour": RateLimit(3600, "hour"),
    "rate_limit_per_day": RateLimit(86400, "day"),
}


@dataclass(frozen=True)
class ActionType:
    name: str
    verb: str  # used to build the plain-language summary
    allowed: frozenset[str]
    required: frozenset[str]

    def describe(self) -> str:
        return self.verb


ACTION_TYPES: dict[str, ActionType] = {
    "purchase": ActionType(
        "purchase",
        "spend your money",
        allowed=frozenset(
            {
                "merchant_allowlist",
                "category",
                "max_single_transaction_usd",
                "max_amount_usd",
                "currency",
                "max_uses",
                "rate_limit_per_hour",
                "rate_limit_per_day",
            }
        ),
        # A spend permission with no merchant list and no per-transaction cap is a
        # blank cheque. The language refuses to express one.
        required=frozenset({"merchant_allowlist", "max_single_transaction_usd"}),
    ),
    "send_message": ActionType(
        "send_message",
        "send messages as you",
        allowed=frozenset(
            {"recipient_allowlist", "channel", "max_uses", "rate_limit_per_hour", "rate_limit_per_day"}
        ),
        required=frozenset({"recipient_allowlist"}),
    ),
    "edit_resource": ActionType(
        "edit_resource",
        "change your files",
        allowed=frozenset(
            {"resource_allowlist", "allowed_operations", "max_size_bytes", "max_uses", "rate_limit_per_hour"}
        ),
        required=frozenset({"resource_allowlist", "allowed_operations"}),
    ),
    "api_call": ActionType(
        "api_call",
        "call services on your behalf",
        allowed=frozenset(
            {"endpoint_allowlist", "method_allowlist", "max_uses", "rate_limit_per_hour", "rate_limit_per_day"}
        ),
        required=frozenset({"endpoint_allowlist"}),
    ),
}


class ScopeError(ValueError):
    """The scope is not expressible in SDL v1."""


def validate_scope(scope: Any) -> tuple[ActionType, dict[str, Any]]:
    """Check a scope block at *mint* time. Returns (action_type, constraints).

    This is the issuer-side gate: the consent layer refuses to mint a grant it
    could not later explain or enforce.
    """
    if not isinstance(scope, dict):
        raise ScopeError("scope must be an object")

    action_name = scope.get("action_type")
    action = ACTION_TYPES.get(action_name) if isinstance(action_name, str) else None
    if action is None:
        raise ScopeError(
            f"unknown action_type {action_name!r}; SDL v1 knows: "
            + ", ".join(sorted(ACTION_TYPES))
        )

    constraints = scope.get("constraints")
    if not isinstance(constraints, dict) or not constraints:
        raise ScopeError("scope.constraints must be a non-empty object")

    unknown = set(constraints) - set(CONSTRAINTS)
    if unknown:
        raise ScopeError(f"unknown constraint(s): {', '.join(sorted(unknown))}")

    not_applicable = set(constraints) - set(action.allowed)
    if not_applicable:
        raise ScopeError(
            f"constraint(s) {', '.join(sorted(not_applicable))} do not apply to "
            f"action_type {action.name!r}"
        )

    missing = set(action.required) - set(constraints)
    if missing:
        raise ScopeError(
            f"action_type {action.name!r} requires {', '.join(sorted(missing))}"
        )

    for name, value in constraints.items():
        try:
            CONSTRAINTS[name].validate(value)
        except (ValueError, MoneyError) as exc:
            raise ScopeError(f"{name}: {exc}") from exc

    # A cumulative budget below the per-action cap is almost always a typo, and
    # the plain-language rendering would read as a contradiction.
    per_action = constraints.get("max_single_transaction_usd")
    budget = constraints.get("max_amount_usd")
    if per_action is not None and budget is not None and money(per_action) > money(budget):
        raise ScopeError(
            "max_single_transaction_usd cannot exceed max_amount_usd "
            f"({fmt_money(money(per_action))} > {fmt_money(money(budget))})"
        )

    return action, constraints


# --------------------------------------------------------------------------- #
# plain language
# --------------------------------------------------------------------------- #

# Order the clauses so the sentence reads the way a person would say it, rather
# than in whatever order the JSON happened to arrive.
_CLAUSE_ORDER = [
    "merchant_allowlist",
    "recipient_allowlist",
    "resource_allowlist",
    "endpoint_allowlist",
    "method_allowlist",
    "allowed_operations",
    "category",
    "channel",
    "currency",
    "max_single_transaction_usd",
    "max_size_bytes",
    "max_amount_usd",
    "max_uses",
    "rate_limit_per_hour",
    "rate_limit_per_day",
]


def render_clauses(scope: dict[str, Any]) -> list[str]:
    """Every constraint as its own English clause, in reading order."""
    constraints = scope.get("constraints", {})
    ordered = [n for n in _CLAUSE_ORDER if n in constraints]
    ordered += [n for n in constraints if n not in _CLAUSE_ORDER]
    out = []
    for name in ordered:
        primitive = CONSTRAINTS.get(name)
        # Unknown constraint: say so plainly rather than quietly dropping it. A
        # clause the UI cannot render is a clause the user cannot consent to.
        out.append(
            primitive.render(constraints[name])
            if primitive
            else f"an unrecognised restriction ({name}) that cannot be shown"
        )
    return out


def render_summary(grant_or_request: dict[str, Any]) -> str:
    """A single sentence: what this agent is being allowed to do."""
    scope = grant_or_request.get("scope", {})
    action = ACTION_TYPES.get(scope.get("action_type", ""))
    verb = action.describe() if action else "act on your behalf"
    agent = grant_or_request.get("issued_to") or grant_or_request.get("requested_by", "an agent")
    clauses = render_clauses(scope)
    if not clauses:
        return f"Let {agent} {verb}."
    return f"Let {agent} {verb} — " + "; ".join(clauses) + "."


def render_expiry(expires_at: str) -> str:
    try:
        when = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return f"expires {expires_at}"
    delta = when - datetime.now(timezone.utc)
    hours = delta.total_seconds() / 3600
    if hours < 0:
        return "already expired"
    if hours < 1:
        return f"expires in {int(delta.total_seconds() // 60)} minutes"
    if hours < 48:
        return f"expires in {round(hours)} hours"
    return f"expires in {round(hours / 24)} days"


def action_type_catalogue() -> list[dict[str, Any]]:
    """The vocabulary, for the UI and the pitch: what SDL v1 can express."""
    return [
        {
            "action_type": at.name,
            "summary": at.describe(),
            "constraints": sorted(at.allowed),
            "required": sorted(at.required),
        }
        for at in ACTION_TYPES.values()
    ]
