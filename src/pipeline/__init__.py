from typing import Any

from src.pipeline.cache import (
    cache_enabled,
    load_cached_json,
    load_cached_set,
    response_cache_fresh,
    save_cached_json,
    save_cached_set,
)
from src.pipeline.retry import (
    RetryMetrics,
    RetryPolicy,
    classify_error,
)
from src.pipeline.storage import (
    DISK_SPACE_WARN_BYTES,
    check_disk_space,
    ensure_dir,
    format_json,
    format_jsonl,
    format_lines,
    format_ranked_lines,
    load_config,
    preflight_storage_check,
    read_lines,
    read_scope,
    validate_storage,
    write_json,
    write_jsonl,
    write_lines,
    write_ranked_lines,
)


def __getattr__(name: str) -> Any:
    if name == "main":
        from src.pipeline.runtime import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [name for name in globals() if not name.startswith("_")] + ["main"]
