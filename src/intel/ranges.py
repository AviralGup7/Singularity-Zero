"""CIDR / domain helpers for intel lookups."""

from __future__ import annotations

import ipaddress

from src.intel.ioc import Indicator, IndicatorKind, classify_indicator


def in_cidr(ip: str, cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address in network


def private_indicator(raw: object) -> bool:
    indicator = classify_indicator(raw)
    if indicator.kind is IndicatorKind.IPV4:
        try:
            return ipaddress.ip_address(indicator.value).is_private
        except ValueError:
            return False
    if indicator.kind is IndicatorKind.DOMAIN:
        return indicator.value.endswith(".local") or indicator.value.endswith(".internal")
    return False


def routable(raw: object) -> bool:
    indicator = classify_indicator(raw)
    if indicator.kind is IndicatorKind.UNKNOWN:
        return False
    return not private_indicator(indicator.value)


def group_by_kind(items: list[Indicator]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in items:
        grouped.setdefault(item.kind.value, []).append(item.normalized())
    return grouped
