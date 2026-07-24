"""Configuration service contracts.

This module defines the ``ConfigurationService`` interface, which is the
single entry point for loading, validating, and accessing pipeline
configuration.
"""

from abc import ABC, abstractmethod
from pathlib import Path

from src.core.config.typed_config import ValidatedPipelineConfig


class ConfigurationService(ABC):
    """Interface for pipeline configuration management.

    All production code must obtain configuration through this interface
    rather than importing ``Config`` or ``ValidatedPipelineConfig`` directly.
    """

    @abstractmethod
    def load(self, path: Path | str) -> ValidatedPipelineConfig:
        """Load and validate configuration from a JSON file.

        Args:
            path: Path to the JSON configuration file.

        Returns:
            Loaded and validated configuration instance.
        """

    @abstractmethod
    def get(self) -> ValidatedPipelineConfig:
        """Return the currently active configuration.

        Returns:
            The active configuration instance.

        Raises:
            RuntimeError: If no configuration has been loaded yet.
        """

    @abstractmethod
    def register(self, config: ValidatedPipelineConfig) -> None:
        """Register a configuration instance as the active configuration.

        Args:
            config: The configuration instance to register.
        """
