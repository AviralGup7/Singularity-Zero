import logging

from src.execution.active_manifest import *  # noqa: F403
from src.execution.exploiters import *  # noqa: F403
from src.execution.isolated import *  # noqa: F403
from src.execution.scenario_engine import *  # noqa: F403

logger = logging.getLogger(__name__)

try:
    from src.execution.validators import *  # noqa: F403
except Exception as exc:
    # Validator imports are intentionally optional during child-process bootstrap.
    _VALIDATOR_IMPORT_ERROR = exc
    logger.warning(
        "Failed to import validators: %s. This is normal during child-process bootstrap, "
        "but may indicate missing dependencies if it happens in the main process.",
        exc,
        exc_info=True,
    )

__all__ = [name for name in globals() if not name.startswith("_")]
