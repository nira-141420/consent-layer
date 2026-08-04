"""Hash-chained audit log.

Every request, approval, denial, revocation and verification lands here. Each row
commits to the one before it:

    row_hash = sha256( canonical({ seq, ts, event, actor, token_id, payload, prev_hash }) )

so altering any historic row -- or removing one, or splicing one in -- breaks every
hash from that point forward. That is *tamper-evident*, not tamper-proof: an
attacker with write access can still rewrite the whole chain from the edit onward.
Making that infeasible needs an external anchor (publish the head hash somewhere
you do not control, or countersign each head). Noted as future work rather than
hand-waved -- but `verify_chain` below genuinely detects everything short of a
full rewrite, and the demo shows it catching a single edited row.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json

GENESIS_HASH = "0" * 64


def row_digest(
    seq: int,
    ts: str,
    event: str,
    actor: str,
    token_id: str | None,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "seq": seq,
                "ts": ts,
                "event": event,
                "actor": actor,
                "token_id": token_id,
                "payload": payload,
                "prev_hash": prev_hash,
            }
        )
    ).hexdigest()


def append(
    conn: sqlite3.Connection,
    *,
    ts: str,
    event: str,
    actor: str,
    token_id: str | None,
    payload: dict[str, Any],
) -> int:
    """Append one event. Caller must already hold a write transaction."""
    head = conn.execute(
        "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    seq = (head["seq"] + 1) if head else 1
    prev_hash = head["row_hash"] if head else GENESIS_HASH

    digest = row_digest(seq, ts, event, actor, token_id, payload, prev_hash)
    conn.execute(
        "INSERT INTO audit_log (seq, ts, event, actor, token_id, payload_json,"
        " prev_hash, row_hash) VALUES (?,?,?,?,?,?,?,?)",
        (seq, ts, event, actor, token_id, canonical_json(payload).decode(), prev_hash, digest),
    )
    return seq


@dataclass
class ChainReport:
    intact: bool
    length: int
    head_hash: str
    broken_at: int | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "intact": self.intact,
            "length": self.length,
            "head_hash": self.head_hash,
            "broken_at": self.broken_at,
            "detail": self.detail,
        }


def verify_chain(conn: sqlite3.Connection) -> ChainReport:
    """Recompute the whole chain and report the first inconsistency."""
    rows = conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
    if not rows:
        return ChainReport(True, 0, GENESIS_HASH, detail="log is empty")

    prev_hash = GENESIS_HASH
    for index, row in enumerate(rows, start=1):
        if row["seq"] != index:
            return ChainReport(
                False,
                len(rows),
                rows[-1]["row_hash"],
                broken_at=row["seq"],
                detail=f"sequence gap: expected entry {index}, found {row['seq']} "
                "— an entry was removed or inserted",
            )
        if row["prev_hash"] != prev_hash:
            return ChainReport(
                False,
                len(rows),
                rows[-1]["row_hash"],
                broken_at=row["seq"],
                detail=f"entry {row['seq']} does not link to the entry before it",
            )
        expected = row_digest(
            row["seq"],
            row["ts"],
            row["event"],
            row["actor"],
            row["token_id"],
            json.loads(row["payload_json"]),
            row["prev_hash"],
        )
        if expected != row["row_hash"]:
            return ChainReport(
                False,
                len(rows),
                rows[-1]["row_hash"],
                broken_at=row["seq"],
                detail=f"entry {row['seq']} has been altered since it was written "
                "— its contents no longer match its hash",
            )
        prev_hash = row["row_hash"]

    return ChainReport(
        True, len(rows), prev_hash, detail=f"all {len(rows)} entries verified"
    )
