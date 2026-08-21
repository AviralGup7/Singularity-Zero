"""Build a detector bundle for a scan mode."""

from __future__ import annotations

from dataclasses import dataclass

from src.detection.policy import keys_for_mode
from src.detection.taxonomy import classify_key


@dataclass(frozen=True, slots=True)
class DetectorBundle:
    mode: str
    keys: tuple[str, ...]

    @property
    def size(self) -> int:
        return len(self.keys)

    def families(self) -> dict[str, int]:
        tallies: dict[str, int] = {}
        for key in self.keys:
            family = classify_key(key).family
            tallies[family] = tallies.get(family, 0) + 1
        return tallies


def bundle_for(mode: str) -> DetectorBundle:
    return DetectorBundle(mode=mode, keys=tuple(keys_for_mode(mode)))
