from __future__ import annotations

from src.learning.feedback import Feedback, FeedbackBook, FeedbackLabel
from src.learning.fp_rules import fp_score, likely_false_positive


def test_example_host_is_likely_fp() -> None:
    assert likely_false_positive("XSS on example.com", "n/a")
    assert fp_score("Possible XSS") >= 0.0


def test_feedback_book_fp_rate() -> None:
    book = FeedbackBook()
    book.add(Feedback("f1", FeedbackLabel.FALSE_POSITIVE, "ada"))
    book.add(Feedback("f2", FeedbackLabel.TRUE_POSITIVE, "ada"))
    assert book.fp_rate() == 0.5
    assert book.latest_label("f1") is FeedbackLabel.FALSE_POSITIVE
