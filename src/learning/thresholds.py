"""Adaptive confidence thresholds from analyst feedback."""

from __future__ import annotations

from src.learning.feedback import FeedbackBook, FeedbackLabel


def suggested_threshold(book: FeedbackBook, *, default: float = 0.55) -> float:
    if len(book) < 8:
        return default
    rate = book.fp_rate()
    if rate >= 0.4:
        return min(0.85, default + 0.15)
    if rate <= 0.1:
        return max(0.35, default - 0.1)
    return default


def suppress_finding(book: FeedbackBook, finding_id: str) -> bool:
    return book.latest_label(finding_id) is FeedbackLabel.FALSE_POSITIVE
