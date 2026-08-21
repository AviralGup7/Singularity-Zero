"""Map detector keys onto a stable taxonomy."""

from __future__ import annotations

from dataclasses import dataclass

from src.detection.catalog import list_finding_spec_keys
from src.detection.family_rules import family_for


@dataclass(frozen=True, slots=True)
class Taxon:
    key: str
    family: str
    surface: str


_SURFACES: tuple[tuple[str, str], ...] = (
    ("graphql", "graphql"),
    ("grpc", "grpc"),
    ("websocket", "websocket"),
    ("jwt", "http-auth"),
    ("cookie", "http-auth"),
    ("dns", "dns"),
    ("tls", "tls"),
)


def classify_key(key: str) -> Taxon:
    lowered = key.lower()
    family = family_for(key)
    surface = "http"
    for needle, label in _SURFACES:
        if needle in lowered:
            surface = label
            break
    return Taxon(key=key, family=family, surface=surface)


def catalog_taxonomy() -> list[Taxon]:
    return [classify_key(key) for key in list_finding_spec_keys()]


def families() -> dict[str, int]:
    tallies: dict[str, int] = {}
    for taxon in catalog_taxonomy():
        tallies[taxon.family] = tallies.get(taxon.family, 0) + 1
    return tallies
