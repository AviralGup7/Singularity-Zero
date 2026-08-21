"""Indicator-of-compromise value objects."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum


class IndicatorKind(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    CVE = "cve"
    UNKNOWN = "unknown"


_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


@dataclass(frozen=True, slots=True)
class Indicator:
    kind: IndicatorKind
    value: str

    def normalized(self) -> str:
        if self.kind is IndicatorKind.HASH:
            return self.value.lower()
        if self.kind is IndicatorKind.CVE:
            return self.value.upper()
        if self.kind is IndicatorKind.DOMAIN:
            return self.value.lower().rstrip(".")
        return self.value


def classify_indicator(raw: object) -> Indicator:
    value = str(raw or "").strip()
    if not value:
        return Indicator(IndicatorKind.UNKNOWN, "")
    if _CVE_RE.match(value):
        return Indicator(IndicatorKind.CVE, value.upper())
    if _HASH_RE.match(value):
        return Indicator(IndicatorKind.HASH, value.lower())
    if _EMAIL_RE.match(value):
        return Indicator(IndicatorKind.EMAIL, value.lower())
    if "://" in value:
        return Indicator(IndicatorKind.URL, value)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        parsed = None
    if parsed is not None:
        kind = IndicatorKind.IPV6 if parsed.version == 6 else IndicatorKind.IPV4
        return Indicator(kind, str(parsed))
    if _DOMAIN_RE.match(value):
        return Indicator(IndicatorKind.DOMAIN, value.lower())
    return Indicator(IndicatorKind.UNKNOWN, value)


def host_from_url(url: str) -> str:
    raw = str(url or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    raw = raw.split("@")[-1]
    return raw.split(":")[0]


def related_indicators(indicator: Indicator) -> list[Indicator]:
    extras: list[Indicator] = [indicator]
    if indicator.kind is IndicatorKind.URL:
        host = host_from_url(indicator.value)
        extras.append(classify_indicator(host))
    return extras


def extract_indicators(text: object) -> list[Indicator]:
    blob = str(text or "")
    found: list[Indicator] = []
    seen: set[str] = set()
    for token in re.findall(r"[A-Za-z0-9._:/-]+", blob):
        indicator = classify_indicator(token)
        for item in related_indicators(indicator):
            if item.kind is IndicatorKind.UNKNOWN:
                continue
            key = f"{item.kind}:{item.normalized()}"
            if key in seen:
                continue
            seen.add(key)
            found.append(item)
    return found
