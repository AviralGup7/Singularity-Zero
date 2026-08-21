"""Protocol handshake between the Security Console UI and the gateway."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.integration.errors import ErrorCode, IntegrationError, bad_request
from src.integration.protocol import (
    CLIENT_NAME,
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    protocol_compatible,
)


@dataclass(frozen=True, slots=True)
class HandshakeOffer:
    client: str
    protocol: str
    kind: str
    name: str
    role: str

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> HandshakeOffer:
        client = str(payload.get("client") or CLIENT_NAME).strip() or CLIENT_NAME
        protocol = str(payload.get("protocol") or PROTOCOL_VERSION).strip() or PROTOCOL_VERSION
        kind = str(payload.get("kind") or "demo").strip().lower() or "demo"
        if kind not in {"demo", "guest", "jwt", "api_key"}:
            raise bad_request("unsupported session kind", kind=kind)
        name = str(payload.get("name") or payload.get("subject") or "Demo Analyst").strip()
        role = str(payload.get("role") or "analyst").strip().lower() or "analyst"
        if not protocol_compatible(protocol):
            raise IntegrationError(
                ErrorCode.PROTOCOL,
                f"incompatible protocol {protocol}",
                details={"server": PROTOCOL_VERSION, "client": protocol},
            )
        return cls(client=client, protocol=protocol, kind=kind, name=name or "Demo Analyst", role=role)


def accept(offer: HandshakeOffer) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_VERSION,
        "protocol_name": PROTOCOL_NAME,
        "client": offer.client,
        "kind": offer.kind,
        "accepted": True,
    }
