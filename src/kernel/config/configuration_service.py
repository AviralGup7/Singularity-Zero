"""Canonical configuration service implementation.

This module provides ``ConfigurationServiceImpl``, the concrete
implementation of ``ConfigurationService`` that uses
``ValidatedPipelineConfig`` as the underlying configuration model.
"""

from pathlib import Path

from src.core.config.typed_config import ValidatedPipelineConfig, load_config
from src.core_domain.contracts.configuration import ConfigurationService


class ConfigurationServiceImpl(ConfigurationService):
    """Concrete implementation of ``ConfigurationService``.

    Wraps the canonical ``ValidatedPipelineConfig`` loading logic and
    provides a single point of access for configuration data.
    """

    def __init__(self) -> None:
        self._config: ValidatedPipelineConfig | None = None

    def load(self, path: Path | str) -> ValidatedPipelineConfig:
        """Load and validate configuration from a JSON file.

        Args:
            path: Path to the JSON configuration file.

        Returns:
            Loaded and validated configuration instance.
        """
        self._config = load_config(path)
        return self._config

    def get(self) -> ValidatedPipelineConfig:
        """Return the currently active configuration.

        Returns:
            The active configuration instance.

        Raises:
            RuntimeError: If no configuration has been loaded yet.
        """
        if self._config is None:
            raise RuntimeError("No configuration loaded. Call load() or register() first.")
        return self._config

    def register(self, config: ValidatedPipelineConfig) -> None:
        """Register a configuration instance as the active configuration.

        Args:
            config: The configuration instance to register.
        """
        self._config = config
