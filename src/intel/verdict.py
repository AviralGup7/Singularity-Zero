"""Aggregate feed verdicts into a single console verdict."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Verdict(StrEnum):
    UNKNOWN = "unknown"
    HARMLESS = "harmless"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


_RANK = {
    Verdict.UNKNOWN: 0,
    Verdict.HARMLESS: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}


@dataclass(frozen=True, slots=True)
class FeedVote:
    source: str
    verdict: Verdict
    score: float = 0.0
    tags: tuple[str, ...] = ()


def parse_verdict(raw: object) -> Verdict:
    value = str(raw or "").strip().lower()
    aliases = {
        "clean": Verdict.HARMLESS,
        "benign": Verdict.HARMLESS,
        "ok": Verdict.HARMLESS,
        "bad": Verdict.MALICIOUS,
        "malware": Verdict.MALICIOUS,
        "malicious": Verdict.MALICIOUS,
        "suspicious": Verdict.SUSPICIOUS,
        "suspect": Verdict.SUSPICIOUS,
        "undetected": Verdict.UNKNOWN,
        "unknown": Verdict.UNKNOWN,
        "harmless": Verdict.HARMLESS,
    }
    return aliases.get(value, Verdict.UNKNOWN)


def combine_votes(votes: list[FeedVote]) -> Verdict:
    if not votes:
        return Verdict.UNKNOWN
    malicious = sum(1 for vote in votes if vote.verdict is Verdict.MALICIOUS)
    suspicious = sum(1 for vote in votes if vote.verdict is Verdict.SUSPICIOUS)
    if malicious >= 1:
        return Verdict.MALICIOUS
    if suspicious >= 1:
        return Verdict.SUSPICIOUS
    if any(vote.verdict is Verdict.HARMLESS for vote in votes) and malicious == 0:
        return Verdict.HARMLESS
    return Verdict.UNKNOWN


def worst(*verdicts: Verdict) -> Verdict:
    if not verdicts:
        return Verdict.UNKNOWN
    return max(verdicts, key=lambda item: _RANK[item])
