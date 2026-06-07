"""mDNS-based P2P worker discovery for local-mesh orchestration.

Uses Zeroconf to register this worker as a service and discover other
workers on the local network.  All advertised TXT records are HMAC-
signed with the same shared secret used by the gossip engine so an
attacker on the LAN cannot impersonate a peer, and an allowlist
(optionally derived from a SHA-256 prefix of the secret) keeps unknown
node IDs from polluting the local mesh.

This module is intentionally side-effect free until ``register()`` or
``start_discovery()`` is called so it is safe to import on hosts without
a working mDNS stack (e.g. CI, containers with no Avahi).
"""

import hashlib
import hmac
import json
import logging
import os
import socket
import time
from typing import Any

from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

logger = logging.getLogger(__name__)

SERVICE_TYPE = "_cybersec-pipeline._tcp.local."

# TXT record keys we publish.  Keep them short: mDNS imposes a 255-byte
# single-record and 1300-byte aggregate limit per packet.
_TXT_NODE_ID = "node_id"
_TXT_CAPABILITIES = "caps"
_TXT_REGION = "region"
_TXT_ZONE = "zone"
_TXT_BANDWIDTH = "bw"
_TXT_CAPACITY = "cap"
_TXT_VERSION_VECTOR = "vv"
_TXT_SIGNATURE = "sig"
_TXT_TIMESTAMP = "ts"
_TXT_SCHEMA = "md"
_MAX_METADATA_VALUE = 200
_DEFAULT_SCHEMA = 1
DEFAULT_SCHEMA = _DEFAULT_SCHEMA


def _env_allowlist() -> set[str]:
    """Return the configured allowlist of node IDs, if any."""
    raw = os.getenv("MESH_PEER_ALLOWLIST", "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def _derive_allowlist_from_secret(secret: str | None) -> set[str]:
    """Generate an implicit allowlist from the mesh secret.

    Operators who don't enumerate ``MESH_PEER_ALLOWLIST`` still want
    *something* stronger than "accept any node that responds"; we use
    the first 16 hex chars of ``sha256(secret)`` as the namespace
    prefix and require discovered TXT records to carry it.  This stops
    accidental mesh-joins from unrelated LAN services that happen to
    use the same service type.
    """
    if not secret:
        return set()
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
    return {f"ns-{digest}"}


class WorkerListener(ServiceListener):
    """Listener for mDNS service events with HMAC verification."""

    def __init__(
        self,
        callback: Any = None,
        *,
        secret: str | None = None,
        allowlist: set[str] | None = None,
        clock_skew_sec: float = 60.0,
    ) -> None:
        self.callback = callback
        self.discovered_services: dict[str, dict[str, Any]] = {}
        self._secret = secret.encode("utf-8") if secret else b""
        self._allowlist = allowlist if allowlist is not None else set()
        self._clock_skew_sec = clock_skew_sec

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            self._handle_service(info)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            self._handle_service(info)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name in self.discovered_services:
            del self.discovered_services[name]
            logger.info("Worker service removed: %s", name)
            if self.callback:
                self.callback("remove", name)

    def _handle_service(self, info: ServiceInfo) -> None:
        name = info.name
        metadata: dict[str, str] = {}
        if info.properties:
            for k, v in info.properties.items():
                key = k.decode("utf-8") if isinstance(k, bytes) else str(k)
                val = v.decode("utf-8") if isinstance(v, bytes) else str(v)
                metadata[key] = val

        node_id = metadata.get(_TXT_NODE_ID) or name.split(".")[0]
        if not self._is_authorised(node_id, metadata):
            logger.warning(
                "Dropping unauthorised mDNS worker advert name=%s node_id=%s",
                name,
                node_id,
            )
            return

        try:
            addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
        except (OSError, ValueError) as exc:
            logger.warning("Discarding mDNS service with bad addresses: %s", exc)
            return

        entry = {
            "name": name,
            "node_id": node_id,
            "addresses": addresses,
            "port": info.port,
            "metadata": metadata,
            "capabilities": _split_caps(metadata.get(_TXT_CAPABILITIES)),
            "region": metadata.get(_TXT_REGION, ""),
            "zone": metadata.get(_TXT_ZONE, ""),
            "bandwidth_mbps": _safe_int(metadata.get(_TXT_BANDWIDTH)),
            "capacity_weight": _safe_float(metadata.get(_TXT_CAPACITY)),
            "version_vector": _split_caps(metadata.get(_TXT_VERSION_VECTOR)),
            "verified": bool(self._secret),
        }
        self.discovered_services[name] = entry
        logger.info(
            "Worker service discovered/updated: %s at %s:%d", name, addresses, info.port
        )
        if self.callback:
            self.callback("add", entry)

    def _is_authorised(self, node_id: str, metadata: dict[str, str]) -> bool:
        """Verify HMAC signature and enforce the allowlist.

        Both checks must pass:

        1. If a secret is configured, the ``sig`` TXT record must match
           ``hmac_sha256(secret, node_id|ts|caps|region|...)``.
        2. The node id (or the implicit ``ns-`` namespace) must be in
           the allowlist.
        """
        if self._allowlist and node_id not in self._allowlist:
            # Implicit namespace allowlist - accept if metadata carries it.
            namespace = metadata.get("ns", "")
            if not namespace or namespace not in self._allowlist:
                return False

        if not self._secret:
            return True

        signature = metadata.get(_TXT_SIGNATURE, "")
        timestamp = metadata.get(_TXT_TIMESTAMP, "")
        schema = metadata.get(_TXT_SCHEMA, str(_DEFAULT_SCHEMA))
        if not signature or not timestamp:
            return False
        try:
            ts = float(timestamp)
        except (TypeError, ValueError):
            return False
        if abs(time.time() - ts) > self._clock_skew_sec:
            return False

        payload = _canonical_payload(node_id, ts, schema, metadata)
        expected = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False
        return True


def _split_caps(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item for item in raw.split(",") if item]


def _safe_int(raw: str | None) -> int:
    if not raw:
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _safe_float(raw: str | None) -> float:
    if not raw:
        return 0.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def _canonical_payload(
    node_id: str, timestamp: float, schema: str, metadata: dict[str, str]
) -> bytes:
    """Build a deterministic byte string for HMAC verification."""
    keys = (
        _TXT_NODE_ID,
        _TXT_CAPABILITIES,
        _TXT_REGION,
        _TXT_ZONE,
        _TXT_BANDWIDTH,
        _TXT_CAPACITY,
        _TXT_VERSION_VECTOR,
    )
    parts = [f"v={schema}", f"id={node_id}", f"ts={timestamp:.0f}"]
    for key in keys:
        parts.append(f"{key}={metadata.get(key, '')}")
    return "|".join(parts).encode("utf-8")


def _sign_metadata(
    node_id: str, secret: bytes, metadata: dict[str, str]
) -> tuple[str, float]:
    ts = time.time()
    schema = str(_DEFAULT_SCHEMA)
    payload = _canonical_payload(node_id, ts, schema, metadata)
    sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return sig, ts


class WorkerDiscovery:
    """Manages mDNS registration and discovery of pipeline workers.

    Args:
        worker_id: Unique identifier for this worker.
        port: Port the worker is listening on (for API/management).
        metadata: Additional key-value pairs to announce via mDNS.
        secret: Shared secret used to sign/verify TXT records.  When
            ``None`` signatures are skipped (insecure; tests only).
        allowlist: Set of node IDs permitted to join.  Empty means
            "accept anything that passes the signature check".
        on_change: Async-friendly callback receiving ``(action, payload)``
            where ``action`` is ``"add"`` or ``"remove"``.
        enable: When ``False``, all operations are no-ops.  Useful for
            CI / single-node deployments.
    """

    def __init__(
        self,
        worker_id: str,
        port: int = 8008,
        metadata: dict[str, Any] | None = None,
        *,
        secret: str | None = None,
        allowlist: set[str] | None = None,
        on_change: Any = None,
        enable: bool = True,
    ) -> None:
        self.worker_id = worker_id
        self.port = port
        self.metadata = dict(metadata or {})
        self._secret = secret.encode("utf-8") if secret else b""
        self._allowlist = (
            set(allowlist) if allowlist is not None else _env_allowlist()
        )
        if not self._allowlist and self._secret:
            self._allowlist = _derive_allowlist_from_secret(secret)
        self._on_change = on_change
        self._enable = enable
        self.zeroconf: Zeroconf | None = None
        self.listener: WorkerListener | None = None
        self.browser: ServiceBrowser | None = None
        self._known_workers: dict[str, dict[str, Any]] = {}
        self._registered = False
        self._browsing = False

    def register(self) -> bool:
        """Register this worker as an mDNS service.

        Returns ``True`` if registration succeeded (or was skipped
        because discovery is disabled); ``False`` on transport errors.
        """
        if not self._enable:
            return False
        if self._registered:
            return True
        try:
            self.zeroconf = self.zeroconf or Zeroconf()
        except Exception as exc:  # noqa: BLE001 - platform-dependent
            logger.warning("Zeroconf init failed; mDNS disabled: %s", exc)
            self._enable = False
            return False
        advertised = self._build_advertised_metadata()
        local_ip = self._get_local_ip()
        info = ServiceInfo(
            SERVICE_TYPE,
            f"{self.worker_id}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=advertised,
        )
        try:
            self.zeroconf.register_service(info)
            self._registered = True
            logger.info(
                "Registered worker %s at %s:%d via mDNS (signed=%s)",
                self.worker_id,
                local_ip,
                self.port,
                bool(self._secret),
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to register worker via mDNS: %s", exc)
            return False

    def start_discovery(self) -> bool:
        """Start browsing for other workers on the local network."""
        if not self._enable:
            return False
        if self._browsing:
            return True
        try:
            self.zeroconf = self.zeroconf or Zeroconf()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Zeroconf init failed; mDNS disabled: %s", exc)
            self._enable = False
            return False
        self.listener = WorkerListener(
            self._handle_change,
            secret=self._secret.decode("utf-8") if self._secret else None,
            allowlist=self._allowlist,
        )
        try:
            self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self.listener)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to start mDNS browser: %s", exc)
            return False
        self._browsing = True
        logger.info(
            "Started mDNS discovery for service type %s (signed=%s, allowlist_size=%d)",
            SERVICE_TYPE,
            bool(self._secret),
            len(self._allowlist),
        )
        return True

    def discover(self, timeout: float = 2.0) -> list[dict[str, Any]]:
        """Find other workers and return their info."""
        if not self._enable:
            return []
        if not self._browsing:
            self.start_discovery()
        # Non-blocking: we already have a ServiceBrowser; just wait for
        # the listeners to drain.  Use short sleeps so a synchronous
        # caller still gets results.
        end = time.time() + timeout
        while time.time() < end:
            time.sleep(min(0.1, end - time.time()))
        if self.listener is None:
            return []
        return [v for v in self.listener.discovered_services.values() if v["verified"]]

    def _handle_change(self, action: str, data: Any) -> None:
        if action == "add":
            node_id = data.get("node_id", data.get("name", ""))
            self._known_workers[node_id] = data
        elif action == "remove" and isinstance(data, str):
            self._known_workers.pop(data, None)
        if self._on_change is not None:
            try:
                self._on_change(action, data)
            except Exception:  # noqa: BLE001 - callback is user code
                logger.exception("mDNS on_change callback raised")

    def _build_advertised_metadata(self) -> dict[str, str]:
        """Build the TXT record dict, signing it when a secret is set."""
        out: dict[str, str] = {
            _TXT_NODE_ID: _truncate(self.worker_id),
            _TXT_SCHEMA: str(_DEFAULT_SCHEMA),
        }
        capabilities = self.metadata.get("capabilities") or self.metadata.get("caps")
        if capabilities:
            out[_TXT_CAPABILITIES] = _truncate(",".join(capabilities))
        region = self.metadata.get("region", "")
        if region:
            out[_TXT_REGION] = _truncate(region)
        zone = self.metadata.get("zone", "")
        if zone:
            out[_TXT_ZONE] = _truncate(zone)
        bandwidth = self.metadata.get("bandwidth_mbps") or self.metadata.get("bw")
        if bandwidth is not None:
            out[_TXT_BANDWIDTH] = _truncate(str(bandwidth))
        capacity = self.metadata.get("capacity_weight") or self.metadata.get("cap")
        if capacity is not None:
            out[_TXT_CAPACITY] = _truncate(str(capacity))
        version_vector = self.metadata.get("version_vector") or self.metadata.get("vv")
        if version_vector:
            if isinstance(version_vector, dict):
                pairs = [f"{k}={v}" for k, v in sorted(version_vector.items())]
                rendered = ",".join(pairs)
            else:
                rendered = str(version_vector)
            out[_TXT_VERSION_VECTOR] = _truncate(rendered)
        if self._allowlist:
            # Surface the namespace marker so listeners can enforce the
            # implicit allowlist derived from the mesh secret.
            namespaces = sorted(
                tag for tag in self._allowlist if tag.startswith("ns-")
            )
            if namespaces:
                out["ns"] = namespaces[0]
        if self._secret:
            sig, ts = _sign_metadata(self.worker_id, self._secret, out)
            out[_TXT_SIGNATURE] = sig
            out[_TXT_TIMESTAMP] = f"{ts:.0f}"
        return out

    def _get_local_ip(self) -> str:
        """Get the primary local IP address (best effort)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return str(ip)

    def shutdown(self) -> None:
        """Unregister services and close Zeroconf."""
        if not self._enable:
            return
        try:
            if self.browser:
                self.browser.cancel()
                self.browser = None
            if self.zeroconf is not None:
                self.zeroconf.unregister_all_services()
                self.zeroconf.close()
                self.zeroconf = None
            self._registered = False
            self._browsing = False
            logger.info("mDNS discovery shut down")
        except Exception as exc:  # noqa: BLE001
            logger.error("Error during mDNS shutdown: %s", exc)

    # ---------------------------------------------------------------- helpers

    @property
    def is_enabled(self) -> bool:
        return self._enable

    def known_workers(self) -> dict[str, dict[str, Any]]:
        return dict(self._known_workers)


def _truncate(value: str, limit: int = _MAX_METADATA_VALUE) -> str:
    if len(value) <= limit:
        return value
    return value[:limit]


# Re-export the helpers for tests that want to construct payload/sign
# values directly.
__all__ = [
    "WorkerDiscovery",
    "WorkerListener",
    "SERVICE_TYPE",
    "DEFAULT_SCHEMA",
    "_canonical_payload",
    "_sign_metadata",
    "_env_allowlist",
    "_derive_allowlist_from_secret",
]


# Silence unused-import warning for json in environments where
# additional payload formats are desired.
_ = json
