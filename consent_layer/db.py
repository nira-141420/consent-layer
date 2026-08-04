"""SQLite storage for requests, grants, redemptions and the audit log.

The one non-obvious thing in here is `write_txn`: redemption has to be atomic.
Checking "have we used this 3 times yet?" and then recording a fourth use as two
separate statements is a textbook time-of-check/time-of-use bug -- two concurrent
requests both read 2, both decide they are fine, and a max_uses:3 grant gets spent
four times. Every redemption therefore runs inside a single `BEGIN IMMEDIATE`
transaction that covers the check *and* the write.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Iterator

from . import audit
from .sdl import Denial, MoneyError, money

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    request_id      TEXT PRIMARY KEY,
    requested_by    TEXT NOT NULL,
    purpose         TEXT NOT NULL,
    scope_json      TEXT NOT NULL,
    ttl_seconds     INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    status          TEXT NOT NULL,          -- pending | approved | denied
    decided_at      TEXT,
    decision_note   TEXT,
    token_id        TEXT
);

CREATE TABLE IF NOT EXISTS grants (
    token_id        TEXT PRIMARY KEY,
    request_id      TEXT,
    issuer          TEXT NOT NULL,
    issued_to       TEXT NOT NULL,
    issued_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    action_type     TEXT NOT NULL,
    grant_json      TEXT NOT NULL,
    revoked_at      TEXT,
    revoked_reason  TEXT
);

CREATE TABLE IF NOT EXISTS redemptions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id        TEXT NOT NULL,
    action_id       TEXT NOT NULL,
    verifier        TEXT NOT NULL,
    action_json     TEXT NOT NULL,
    decided_at      TEXT NOT NULL,
    allowed         INTEGER NOT NULL,
    deny_code       TEXT,
    deny_reason     TEXT,
    UNIQUE (token_id, action_id)
);

CREATE INDEX IF NOT EXISTS redemptions_token
    ON redemptions (token_id, allowed);

CREATE TABLE IF NOT EXISTS audit_log (
    seq             INTEGER PRIMARY KEY,
    ts              TEXT NOT NULL,
    event           TEXT NOT NULL,
    actor           TEXT NOT NULL,
    token_id        TEXT,
    payload_json    TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    row_hash        TEXT NOT NULL
);
"""


def now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def from_iso(text: str) -> datetime:
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # -- transactions --------------------------------------------------------

    @contextmanager
    def write_txn(self) -> Iterator[sqlite3.Connection]:
        """Exclusive write transaction. Rolls back on any exception."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    @property
    def read(self) -> sqlite3.Connection:
        return self._conn

    # -- scope requests ------------------------------------------------------

    def create_request(
        self, *, requested_by: str, purpose: str, scope: dict, ttl_seconds: int
    ) -> dict:
        request_id = new_id("req")
        ts = to_iso(now())
        with self.write_txn() as conn:
            conn.execute(
                "INSERT INTO requests (request_id, requested_by, purpose, scope_json,"
                " ttl_seconds, created_at, status) VALUES (?,?,?,?,?,?, 'pending')",
                (request_id, requested_by, purpose, json.dumps(scope), ttl_seconds, ts),
            )
            audit.append(
                conn,
                ts=ts,
                event="scope_requested",
                actor=requested_by,
                token_id=None,
                payload={
                    "request_id": request_id,
                    "purpose": purpose,
                    "scope": scope,
                    "ttl_seconds": ttl_seconds,
                },
            )
        return self.get_request(request_id)  # type: ignore[return-value]

    def get_request(self, request_id: str) -> dict | None:
        row = self.read.execute(
            "SELECT * FROM requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        return _request_row(row) if row else None

    def list_requests(self, status: str | None = None) -> list[dict]:
        if status:
            rows = self.read.execute(
                "SELECT * FROM requests WHERE status = ? ORDER BY created_at DESC",
                (status,),
            ).fetchall()
        else:
            rows = self.read.execute(
                "SELECT * FROM requests ORDER BY created_at DESC"
            ).fetchall()
        return [_request_row(r) for r in rows]

    def decide_request(
        self,
        request_id: str,
        *,
        approved: bool,
        note: str,
        actor: str,
        grant: dict | None = None,
    ) -> None:
        """Record a human decision, and store the minted grant if approved."""
        ts = to_iso(now())
        with self.write_txn() as conn:
            row = conn.execute(
                "SELECT status FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise KeyError(request_id)
            if row["status"] != "pending":
                raise ValueError(f"request already {row['status']}")

            token_id = grant["token_id"] if grant else None
            conn.execute(
                "UPDATE requests SET status = ?, decided_at = ?, decision_note = ?,"
                " token_id = ? WHERE request_id = ?",
                ("approved" if approved else "denied", ts, note, token_id, request_id),
            )
            if grant is not None:
                conn.execute(
                    "INSERT INTO grants (token_id, request_id, issuer, issued_to,"
                    " issued_at, expires_at, action_type, grant_json)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (
                        grant["token_id"],
                        request_id,
                        grant["issuer"],
                        grant["issued_to"],
                        grant["issued_at"],
                        grant["expires_at"],
                        grant["scope"]["action_type"],
                        json.dumps(grant),
                    ),
                )
            audit.append(
                conn,
                ts=ts,
                event="consent_granted" if approved else "consent_denied",
                actor=actor,
                token_id=token_id,
                payload={
                    "request_id": request_id,
                    "note": note,
                    **({"expires_at": grant["expires_at"]} if grant else {}),
                },
            )

    # -- grants --------------------------------------------------------------

    def get_grant(self, token_id: str) -> dict | None:
        row = self.read.execute(
            "SELECT * FROM grants WHERE token_id = ?", (token_id,)
        ).fetchone()
        return _grant_row(row) if row else None

    def list_grants(self) -> list[dict]:
        rows = self.read.execute(
            "SELECT * FROM grants ORDER BY issued_at DESC"
        ).fetchall()
        return [_grant_row(r) for r in rows]

    def revoke(self, token_id: str, *, reason: str, actor: str) -> dict:
        ts = to_iso(now())
        with self.write_txn() as conn:
            row = conn.execute(
                "SELECT revoked_at FROM grants WHERE token_id = ?", (token_id,)
            ).fetchone()
            if row is None:
                raise KeyError(token_id)
            if row["revoked_at"]:
                return {"token_id": token_id, "revoked_at": row["revoked_at"],
                        "already_revoked": True}
            conn.execute(
                "UPDATE grants SET revoked_at = ?, revoked_reason = ? WHERE token_id = ?",
                (ts, reason, token_id),
            )
            audit.append(
                conn,
                ts=ts,
                event="consent_revoked",
                actor=actor,
                token_id=token_id,
                payload={"reason": reason},
            )
        return {"token_id": token_id, "revoked_at": ts, "already_revoked": False}

    def revocation_status(self, token_id: str) -> dict:
        """The live check a verifier makes. The one thing a token cannot carry itself."""
        row = self.read.execute(
            "SELECT revoked_at, revoked_reason FROM grants WHERE token_id = ?",
            (token_id,),
        ).fetchone()
        if row is None:
            # Unknown to the issuer. Fail closed: a verifier that treats "never
            # heard of it" as "not revoked" accepts forged token_ids happily.
            return {"known": False, "revoked": True, "reason": "unknown token"}
        return {
            "known": True,
            "revoked": bool(row["revoked_at"]),
            "revoked_at": row["revoked_at"],
            "reason": row["revoked_reason"],
        }

    # -- redemption (the atomic part) ---------------------------------------

    def redeem(
        self,
        *,
        token_id: str,
        action_id: str,
        action: dict[str, Any],
        verifier: str,
        stateful_check: Callable[["SqliteUsage"], Denial | None],
    ) -> dict[str, Any]:
        """Run the usage-dependent checks and record the outcome, atomically.

        `stateful_check` is handed a live view of this grant's history and returns
        a Denial or None. It runs *inside* the write transaction, so the count it
        sees cannot change before the redemption is written.

        Replaying the same `action_id` returns the original decision rather than
        spending the grant twice -- a retried HTTP request is not a second purchase.
        """
        ts = to_iso(now())
        with self.write_txn() as conn:
            prior = conn.execute(
                "SELECT * FROM redemptions WHERE token_id = ? AND action_id = ?",
                (token_id, action_id),
            ).fetchone()
            if prior is not None:
                return {
                    "allowed": bool(prior["allowed"]),
                    "code": prior["deny_code"],
                    "reason": prior["deny_reason"],
                    "decided_at": prior["decided_at"],
                    "replayed": True,
                }

            denial = stateful_check(SqliteUsage(conn, token_id))
            allowed = denial is None
            conn.execute(
                "INSERT INTO redemptions (token_id, action_id, verifier, action_json,"
                " decided_at, allowed, deny_code, deny_reason) VALUES (?,?,?,?,?,?,?,?)",
                (
                    token_id,
                    action_id,
                    verifier,
                    json.dumps(action),
                    ts,
                    1 if allowed else 0,
                    denial.code if denial else None,
                    denial.message if denial else None,
                ),
            )
            audit.append(
                conn,
                ts=ts,
                event="verification_allowed" if allowed else "verification_denied",
                actor=verifier,
                token_id=token_id,
                payload={
                    "action_id": action_id,
                    "action": action,
                    **({} if allowed else {"code": denial.code, "reason": denial.message}),
                },
            )
        return {
            "allowed": allowed,
            "code": denial.code if denial else None,
            "reason": denial.message if denial else None,
            "decided_at": ts,
            "replayed": False,
        }

    def record_rejection(
        self, *, token_id: str | None, denial: Denial, action: dict, verifier: str
    ) -> None:
        """Audit a denial that failed before reaching the usage-dependent stage
        (bad signature, expired, revoked). No redemption row -- nothing was spent."""
        ts = to_iso(now())
        with self.write_txn() as conn:
            audit.append(
                conn,
                ts=ts,
                event="verification_denied",
                actor=verifier,
                token_id=token_id,
                payload={
                    "action": action,
                    "code": denial.code,
                    "reason": denial.message,
                },
            )

    def redemptions_for(self, token_id: str) -> list[dict]:
        rows = self.read.execute(
            "SELECT * FROM redemptions WHERE token_id = ? ORDER BY id ASC", (token_id,)
        ).fetchall()
        return [
            {
                "action_id": r["action_id"],
                "verifier": r["verifier"],
                "action": json.loads(r["action_json"]),
                "decided_at": r["decided_at"],
                "allowed": bool(r["allowed"]),
                "deny_code": r["deny_code"],
                "deny_reason": r["deny_reason"],
            }
            for r in rows
        ]

    # -- audit ---------------------------------------------------------------

    def audit_entries(self, limit: int = 200) -> list[dict]:
        rows = self.read.execute(
            "SELECT * FROM audit_log ORDER BY seq ASC LIMIT ?", (limit,)
        ).fetchall()
        return [
            {
                "seq": r["seq"],
                "ts": r["ts"],
                "event": r["event"],
                "actor": r["actor"],
                "token_id": r["token_id"],
                "payload": json.loads(r["payload_json"]),
                "prev_hash": r["prev_hash"],
                "row_hash": r["row_hash"],
            }
            for r in rows
        ]

    def verify_audit_chain(self) -> dict:
        return audit.verify_chain(self.read).as_dict()

    def log_event(self, *, event: str, actor: str, token_id: str | None, payload: dict) -> None:
        with self.write_txn() as conn:
            audit.append(
                conn, ts=to_iso(now()), event=event, actor=actor,
                token_id=token_id, payload=payload,
            )

    def reset(self) -> None:
        """Wipe everything so the demo can be rehearsed repeatedly.

        Clears tables rather than deleting the file -- on Windows an open SQLite
        handle keeps the file locked, so unlink() would fail here.
        """
        with self.write_txn() as conn:
            for table in ("redemptions", "audit_log", "grants", "requests"):
                conn.execute(f"DELETE FROM {table}")
            conn.execute("DELETE FROM sqlite_sequence WHERE name = 'redemptions'")

    def tamper_with_audit_row(self, seq: int) -> bool:
        """DEMO ONLY: edit a historic log entry without fixing its hash, so the
        chain check can be shown catching it. Never ship this endpoint."""
        with self.write_txn() as conn:
            row = conn.execute(
                "SELECT payload_json FROM audit_log WHERE seq = ?", (seq,)
            ).fetchone()
            if row is None:
                return False
            payload = json.loads(row["payload_json"])
            payload["_tampered"] = "this line was inserted directly into the database"
            conn.execute(
                "UPDATE audit_log SET payload_json = ? WHERE seq = ?",
                (json.dumps(payload), seq),
            )
        return True


class SqliteUsage:
    """A UsageView over one grant's successful redemptions, read inside a txn."""

    def __init__(self, conn: sqlite3.Connection, token_id: str) -> None:
        self._conn = conn
        self._token_id = token_id

    def use_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM redemptions WHERE token_id = ? AND allowed = 1",
            (self._token_id,),
        ).fetchone()
        return int(row["n"])

    def total_of(self, field_name: str) -> Decimal:
        rows = self._conn.execute(
            "SELECT action_json FROM redemptions WHERE token_id = ? AND allowed = 1",
            (self._token_id,),
        ).fetchall()
        total = Decimal(0)
        for row in rows:
            value = json.loads(row["action_json"]).get(field_name)
            if value is None:
                continue
            try:
                total += money(value)
            except MoneyError:
                continue
        return total

    def uses_since(self, since: datetime) -> int:
        rows = self._conn.execute(
            "SELECT decided_at FROM redemptions WHERE token_id = ? AND allowed = 1",
            (self._token_id,),
        ).fetchall()
        return sum(1 for r in rows if from_iso(r["decided_at"]) >= since)


def _request_row(row: sqlite3.Row) -> dict:
    return {
        "request_id": row["request_id"],
        "requested_by": row["requested_by"],
        "purpose": row["purpose"],
        "scope": json.loads(row["scope_json"]),
        "ttl_seconds": row["ttl_seconds"],
        "created_at": row["created_at"],
        "status": row["status"],
        "decided_at": row["decided_at"],
        "decision_note": row["decision_note"],
        "token_id": row["token_id"],
    }


def _grant_row(row: sqlite3.Row) -> dict:
    return {
        "token_id": row["token_id"],
        "request_id": row["request_id"],
        "issuer": row["issuer"],
        "issued_to": row["issued_to"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
        "action_type": row["action_type"],
        "grant": json.loads(row["grant_json"]),
        "revoked_at": row["revoked_at"],
        "revoked_reason": row["revoked_reason"],
    }
