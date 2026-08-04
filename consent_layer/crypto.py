"""Ed25519 signing for consent grants.

MVP simplification (called out in the pitch as scaffolding, not the idea): one
hardcoded keypair for one user, persisted to a file beside the database. Real key
custody, rotation and per-user keys are future work -- but the *signature* itself
is genuine Ed25519, not a stub, because the verification story falls apart if the
crypto is fake.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from nacl import signing
from nacl.exceptions import BadSignatureError

from .canonical import signing_payload


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


class SigningError(Exception):
    pass


class Keyring:
    """Holds the issuer's signing key and resolves key_id -> public key.

    In production this split matters: the *signer* half lives with the user's
    consent layer, the *resolver* half is all a merchant needs. The verification
    SDK only ever touches `public_key_for`.
    """

    def __init__(self, seed: bytes, key_id: str) -> None:
        if len(seed) != 32:
            raise SigningError("Ed25519 seed must be 32 bytes")
        self._signing_key = signing.SigningKey(seed)
        self.key_id = key_id
        self._public: dict[str, signing.VerifyKey] = {
            key_id: self._signing_key.verify_key
        }

    # -- issuer side ---------------------------------------------------------

    @property
    def public_key_b64(self) -> str:
        return b64e(bytes(self._signing_key.verify_key))

    def sign_grant(self, grant_body: dict[str, Any]) -> dict[str, str]:
        """Return the `signature` block for an unsigned grant body."""
        raw = self._signing_key.sign(signing_payload(grant_body)).signature
        return {"alg": "Ed25519", "key_id": self.key_id, "value": b64e(raw)}

    # -- verifier side -------------------------------------------------------

    def public_key_for(self, key_id: str) -> signing.VerifyKey | None:
        return self._public.get(key_id)

    def trust(self, key_id: str, public_key_b64: str) -> None:
        """Register a public key a verifier should accept."""
        self._public[key_id] = signing.VerifyKey(b64d(public_key_b64))

    def verify_grant(self, grant: dict[str, Any]) -> tuple[bool, str]:
        """Check a signed grant. Returns (ok, reason-if-not)."""
        sig = grant.get("signature")
        if not isinstance(sig, dict):
            return False, "grant carries no signature block"
        if sig.get("alg") != "Ed25519":
            # Deny by default: an algorithm we do not implement is not a pass.
            return False, f"unsupported signature algorithm {sig.get('alg')!r}"

        key_id = sig.get("key_id")
        verify_key = self.public_key_for(key_id) if isinstance(key_id, str) else None
        if verify_key is None:
            return False, f"unknown signing key {key_id!r}"

        body = {k: v for k, v in grant.items() if k != "signature"}
        try:
            payload = signing_payload(body)
            verify_key.verify(payload, b64d(str(sig.get("value", ""))))
        except (BadSignatureError, ValueError, TypeError):
            return False, "signature does not match grant contents"
        return True, ""


_DEFAULT_KEY_ID = "user:priya@domain.com#key1"


def load_or_create_keyring(path: Path, key_id: str = _DEFAULT_KEY_ID) -> Keyring:
    """Load the demo keypair from `path`, generating it on first run."""
    if path.exists():
        seed = b64d(path.read_text(encoding="ascii").strip())
    else:
        seed = os.urandom(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(b64e(seed), encoding="ascii")
    return Keyring(seed, key_id)
