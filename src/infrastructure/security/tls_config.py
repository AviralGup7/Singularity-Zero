"""TLS Config recommendation settings for server/client contexts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.infrastructure.security.config import SecurityConfig


class TLSConfig:
    """TLS configuration recommendations.

    Provides secure TLS settings for production deployments.
    """

    RECOMMENDED_CIPHERS = (
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305"
    )

    def __init__(self, config: SecurityConfig | None = None) -> None:
        """Initialize TLS configuration.

        Args:
            config: Security configuration (optional).
        """
        if config:
            self.min_version = config.encryption.tls_min_version
            self.ciphers = config.encryption.tls_ciphers
        else:
            self.min_version = "1.2"
            self.ciphers = self.RECOMMENDED_CIPHERS

    def get_ssl_context(self) -> Any:
        """Create a secure SSL context.

        Returns:
            Configured ssl.SSLContext instance.
        """
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_versions = {
            "1.2": ssl.TLSVersion.TLSv1_2,
            "1.3": ssl.TLSVersion.TLSv1_3,
        }
        ctx.minimum_version = tls_versions.get(self.min_version, ssl.TLSVersion.TLSv1_2)
        ctx.set_ciphers(self.ciphers)
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.options |= ssl.OP_NO_RENEGOTIATION
        return ctx

    def get_mtls_server_context(
        self,
        *,
        certfile: str,
        keyfile: str,
        ca_certs: str,
    ) -> Any:
        """Create a server SSL context that requires client certificates."""
        import ssl

        ctx = self.get_ssl_context()
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ctx.load_verify_locations(cafile=ca_certs)
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def get_mtls_client_context(
        self,
        *,
        certfile: str,
        keyfile: str,
        ca_certs: str,
    ) -> Any:
        """Create a client SSL context for mutual TLS service calls."""
        import ssl

        ctx = ssl.create_default_context(cafile=ca_certs)
        ctx.minimum_version = {
            "1.2": ssl.TLSVersion.TLSv1_2,
            "1.3": ssl.TLSVersion.TLSv1_3,
        }.get(self.min_version, ssl.TLSVersion.TLSv1_2)
        ctx.set_ciphers(self.ciphers)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        return ctx

    def get_uvicorn_ssl_kwargs(self) -> dict[str, Any]:
        """Get SSL kwargs for uvicorn.

        Returns:
            Dict of SSL configuration for uvicorn.
        """
        return {
            "ssl_min_version": f"TLSv{self.min_version}",
            "ssl_ciphers": self.ciphers,
        }

    def get_uvicorn_mtls_kwargs(
        self,
        *,
        certfile: str,
        keyfile: str,
        ca_certs: str,
    ) -> dict[str, Any]:
        """Get uvicorn SSL kwargs for a server that requires client certs."""
        import ssl

        kwargs = self.get_uvicorn_ssl_kwargs()
        kwargs.update(
            {
                "ssl_certfile": certfile,
                "ssl_keyfile": keyfile,
                "ssl_ca_certs": ca_certs,
                "ssl_cert_reqs": ssl.CERT_REQUIRED,
            }
        )
        return kwargs

    def get_gunicorn_ssl_kwargs(self) -> dict[str, Any]:
        """Get SSL kwargs for gunicorn.

        Returns:
            Dict of SSL configuration for gunicorn.
        """
        return {
            "ssl_version": 5,
            "ciphers": self.ciphers,
        }
