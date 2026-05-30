import logging

logger = logging.getLogger(__name__)


def compose_signals(*parts: object) -> list[str]:
    """Centralized signal generation helper used across detection logic."""
    signals: list[str] = []
    for part in parts:
        if part is None:
            logger.warning("Received None value directly in compose_signals parts.")
            continue
        if isinstance(part, str):
            value = part.strip()
            if value:
                signals.append(value)
            continue
        if isinstance(part, (list, tuple, set)):
            for item in part:
                if item is None:
                    logger.warning("Received None value nested inside a collection in compose_signals.")
                    continue
                value = str(item).strip()
                if value:
                    signals.append(value)
            continue

    # Optimize deduplication using dict.fromkeys to avoid set constructor overhead
    return sorted(dict.fromkeys(signals))
