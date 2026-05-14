"""Content-type-aware similarity thresholds and helpers."""

__all__ = [
    "CONTENT_TYPE_SIMILARITY_THRESHOLDS",
    "content_type_similarity_threshold",
]

CONTENT_TYPE_SIMILARITY_THRESHOLDS: dict[str, float] = {
    "json": 0.92,
    "html": 0.96,
    "xml": 0.94,
    "text": 0.90,
    "binary": 0.85,
    "default": 0.94,
}


def content_type_similarity_threshold(content_type: str) -> float:
    """Return the appropriate body similarity threshold for the given content type."""
    ct = (content_type or "").lower()
    if "json" in ct:
        return CONTENT_TYPE_SIMILARITY_THRESHOLDS["json"]
    if "html" in ct:
        return CONTENT_TYPE_SIMILARITY_THRESHOLDS["html"]
    if "xml" in ct:
        return CONTENT_TYPE_SIMILARITY_THRESHOLDS["xml"]
    if "text/" in ct:
        return CONTENT_TYPE_SIMILARITY_THRESHOLDS["text"]
    if any(binary in ct for binary in ("octet-stream", "image", "pdf", "zip")):
        return CONTENT_TYPE_SIMILARITY_THRESHOLDS["binary"]
    return CONTENT_TYPE_SIMILARITY_THRESHOLDS["default"]
