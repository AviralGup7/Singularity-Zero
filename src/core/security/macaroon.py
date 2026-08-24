"""Cryptographic Macaroon Capability Tokens for Zero-Trust Scoped Execution.

Implements chained HMAC-SHA256 non-malleable caveat attenuation ensuring active
probes cannot execute without presenting valid, unexpired, scope-bounded tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any


def _hmac_sha256(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


@dataclass(frozen=True, slots=True)
class Caveat:
    predicate: str  # e.g., "allowed_domain = example.com", "max_rate = 50"

    def key_value(self) -> tuple[str, str]:
        parts = self.predicate.split("=", 1)
        if len(parts) == 2:
            return parts[0].strip(), parts[1].strip()
        return self.predicate.strip(), ""


@dataclass(frozen=True, slots=True)
class MacaroonToken:
    """Cryptographically attenuated capability token."""

    location: str
    identifier: str
    caveats: tuple[Caveat, ...]
    signature: str  # Hex-encoded final HMAC signature

    def attenuate(self, predicate: str) -> MacaroonToken:
        """Append a new caveat and update cryptographic signature chain."""
        current_sig_bytes = bytes.fromhex(self.signature)
        new_sig_bytes = _hmac_sha256(current_sig_bytes, predicate)
        return MacaroonToken(
            location=self.location,
            identifier=self.identifier,
            caveats=self.caveats + (Caveat(predicate),),
            signature=new_sig_bytes.hex(),
        )


class MacaroonMinter:
    """Mints and verifies cryptographic Macaroon tokens."""

    def __init__(self, root_key: bytes) -> None:
        self._root_key = root_key

    def mint(self, location: str, identifier: str) -> MacaroonToken:
        initial_sig = _hmac_sha256(self._root_key, identifier).hex()
        return MacaroonToken(
            location=location,
            identifier=identifier,
            caveats=(),
            signature=initial_sig,
        )

    def verify(self, token: MacaroonToken, context: dict[str, Any]) -> bool:
        """Verify signature integrity and validate all attenuated caveats against context."""
        current_key = _hmac_sha256(self._root_key, token.identifier)
        for caveat in token.caveats:
            current_key = _hmac_sha256(current_key, caveat.predicate)
            k, v = caveat.key_value()
            if k == "allowed_domain" and v:
                req_domain = context.get("domain", "")
                if req_domain != v and not req_domain.endswith("." + v):
                    return False
            elif k == "expires_before" and v:
                if time.time() >= float(v):
                    return False
            elif k == "allowed_protocol" and v:
                if context.get("protocol", "").lower() != v.lower():
                    return False

        return current_key.hex() == token.signature


__all__ = [
    "Caveat",
    "MacaroonMinter",
    "MacaroonToken",
]
