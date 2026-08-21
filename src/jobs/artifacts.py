"""Job artifact index."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ArtifactKind(StrEnum):
    CONFIG = "config"
    SCOPE = "scope"
    STDOUT = "stdout"
    STDERR = "stderr"
    REPORT = "report"
    FINDINGS_JSON = "findings_json"
    HAR = "har"
    SCREENSHOT = "screenshot"


@dataclass(slots=True)
class Artifact:
    kind: ArtifactKind
    href: str
    bytes_len: int = 0
    content_type: str = "text/plain"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "href": self.href,
            "bytes": self.bytes_len,
            "content_type": self.content_type,
        }


@dataclass
class ArtifactIndex:
    items: list[Artifact] = field(default_factory=list)

    def add(self, artifact: Artifact) -> None:
        self.items.append(artifact)

    def of_kind(self, kind: ArtifactKind) -> list[Artifact]:
        return [item for item in self.items if item.kind is kind]

    def hrefs(self) -> list[str]:
        return [item.href for item in self.items]

    def to_dict(self) -> dict[str, object]:
        return {"artifacts": [item.to_dict() for item in self.items], "count": len(self.items)}


def default_launcher_artifacts(job_id: str, target_name: str) -> ArtifactIndex:
    index = ArtifactIndex()
    index.add(Artifact(ArtifactKind.CONFIG, f"/_launcher/{job_id}/config.json", content_type="application/json"))
    index.add(Artifact(ArtifactKind.SCOPE, f"/_launcher/{job_id}/scope.txt"))
    index.add(Artifact(ArtifactKind.STDOUT, f"/_launcher/{job_id}/stdout.txt"))
    index.add(Artifact(ArtifactKind.STDERR, f"/_launcher/{job_id}/stderr.txt"))
    index.add(Artifact(ArtifactKind.REPORT, f"/{target_name}/index.html", content_type="text/html"))
    return index
