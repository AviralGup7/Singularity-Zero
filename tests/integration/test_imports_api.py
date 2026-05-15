import asyncio
import json
from pathlib import Path
from types import SimpleNamespace


class DummyUpload:
    def __init__(self, content: bytes):
        self._content = content

    async def read(self) -> bytes:
        return self._content


def test_import_semgrep_writes_file(tmp_path: Path):
    """Call the import_semgrep handler directly with a dummy upload object."""

    from src.dashboard.fastapi.routers.imports import import_semgrep

    sample = {"results": []}
    content = json.dumps(sample).encode("utf-8")

    services = SimpleNamespace(query=SimpleNamespace(output_root=tmp_path))

    res = asyncio.run(
        import_semgrep(
            target_name="mytarget",
            run=None,
            file=DummyUpload(content),
            overwrite=False,
            _auth={"role": "admin"},
            services=services,
        )
    )

    assert res.get("status") == "ok"
    run_dir = tmp_path / res.get("target") / res.get("run")
    assert (run_dir / "semgrep.json").exists()
