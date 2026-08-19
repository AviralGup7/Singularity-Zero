"""Pytest configuration for frontier tests — mocks modules unavailable in CI/sandbox."""

import sys
from unittest.mock import MagicMock

# FrontierWAL import chain pulls in redis, cryptography, and more.
# These modules are not available in the test sandbox.
sys.modules['redis'] = MagicMock()
sys.modules['cryptography'] = MagicMock()
sys.modules['cryptography.exceptions'] = MagicMock()
sys.modules['cryptography.hazmat'] = MagicMock()
sys.modules['cryptography.hazmat.primitives'] = MagicMock()
sys.modules['cryptography.hazmat.primitives.ciphers'] = MagicMock()
sys.modules['cryptography.hazmat.primitives.ciphers.aead'] = MagicMock()
sys.modules['msgspec'] = MagicMock()
# Prevent provisioning service import from pulling more deps
sys.modules['src.infrastructure.queue.redis_config'] = MagicMock()
sys.modules['src.infrastructure.queue.job_queue'] = MagicMock()
sys.modules['src.infrastructure.queue.core'] = MagicMock()
sys.modules['src.infrastructure.queue.redis_client'] = MagicMock()
