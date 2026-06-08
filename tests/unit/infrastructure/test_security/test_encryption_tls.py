import os
import sys

from src.infrastructure.security.encryption import (
    TLSConfig,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestTLSConfig(SecurityTestBase):
    def test_defaults(self) -> None:
        config = TLSConfig()
        assert config.min_version == "1.2"
        assert config.ciphers == TLSConfig.RECOMMENDED_CIPHERS

    def test_from_security_config(self) -> None:
        config = TLSConfig(self.security_config)
        assert config is not None

    def test_get_uvicorn_ssl_kwargs(self) -> None:
        config = TLSConfig()
        kwargs = config.get_uvicorn_ssl_kwargs()
        assert "ssl_min_version" in kwargs
        assert "ssl_ciphers" in kwargs

    def test_get_gunicorn_ssl_kwargs(self) -> None:
        config = TLSConfig()
        kwargs = config.get_gunicorn_ssl_kwargs()
        assert "ssl_version" in kwargs
        assert "ciphers" in kwargs
