def compose_signals(*parts: object) -> list[str]:
    """Centralized signal generation helper used across detection logic."""
    signals: list[str] = []
    for part in parts:
        if isinstance(part, str):
            value = part.strip()
            if value:
                signals.append(value)
            continue
        if isinstance(part, (list, tuple, set)):
            for item in part:
                value = str(item).strip()
                if value:
                    signals.append(value)
    return sorted(set(signals))
