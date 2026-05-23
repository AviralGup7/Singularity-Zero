from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

PluginKind = Literal["analysis", "validator", "scanner", "enrichment", "exporter", "recon"]
SandboxMode = Literal["process", "wasm", "docker"]

PLUGIN_MANIFEST_SCHEMA_VERSION = "1.0"

_PLUGIN_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,96}$")
_ENTRYPOINT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_ALLOWED_KINDS: set[str] = {"analysis", "validator", "scanner", "enrichment", "exporter", "recon"}
_ALLOWED_SANDBOXES: set[str] = {"process", "wasm", "docker"}
_ALLOWED_IMPORT_ROOTS: set[str] = {
    "__future__",
    "base64",
    "collections",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "functools",
    "hashlib",
    "html",
    "ipaddress",
    "itertools",
    "json",
    "math",
    "re",
    "statistics",
    "string",
    "typing",
    "urllib",
}
_BLOCKED_NAMES: set[str] = {
    "__import__",
    "breakpoint",
    "compile",
    "eval",
    "exec",
    "globals",
    "input",
    "locals",
    "open",
    "vars",
}
_BLOCKED_ATTRIBUTES: set[str] = {
    "__bases__",
    "__class__",
    "__code__",
    "__dict__",
    "__globals__",
    "__mro__",
    "__subclasses__",
}


class PluginValidationError(ValueError):
    """Raised when a dropped plugin does not satisfy the SDK contract."""


@dataclass(frozen=True, slots=True)
class PluginManifest:
    id: str
    name: str
    version: str
    kind: PluginKind
    description: str
    group: str = "third-party"
    entrypoint: str = "run"
    enabled_by_default: bool = True
    sandbox: SandboxMode = "process"
    author: str | None = None
    capabilities: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ("finding",)
    timeout_seconds: int = 20
    schema_version: str = PLUGIN_MANIFEST_SCHEMA_VERSION
    source_path: str | None = None
    source_sha256: str | None = None
    status: Literal["loaded", "invalid"] = "loaded"
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def key(self) -> str:
        return self.id.replace(".", "_").replace("-", "_")

    @property
    def slug(self) -> str:
        return self.key

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("capabilities", "tags", "consumes", "produces", "errors"):
            data[key] = list(data[key])
        return data


@dataclass(frozen=True, slots=True)
class DynamicPluginRecord:
    manifest: PluginManifest
    path: Path
    mtime_ns: int
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.manifest.to_dict(),
            "path": str(self.path),
            "mtime_ns": self.mtime_ns,
            "size": self.size,
        }


def manifest(
    *,
    id: str,
    name: str,
    version: str,
    kind: PluginKind,
    description: str,
    group: str = "third-party",
    entrypoint: str = "run",
    enabled_by_default: bool = True,
    sandbox: SandboxMode = "process",
    author: str | None = None,
    capabilities: tuple[str, ...] | list[str] = (),
    tags: tuple[str, ...] | list[str] = (),
    consumes: tuple[str, ...] | list[str] = (),
    produces: tuple[str, ...] | list[str] = ("finding",),
    timeout_seconds: int = 20,
) -> dict[str, Any]:
    """Convenience helper third-party plugins can import for PLUGIN_MANIFEST."""

    return {
        "id": id,
        "name": name,
        "version": version,
        "kind": kind,
        "description": description,
        "group": group,
        "entrypoint": entrypoint,
        "enabled_by_default": enabled_by_default,
        "sandbox": sandbox,
        "author": author,
        "capabilities": list(capabilities),
        "tags": list(tags),
        "consumes": list(consumes),
        "produces": list(produces),
        "timeout_seconds": timeout_seconds,
        "schema_version": PLUGIN_MANIFEST_SCHEMA_VERSION,
    }


def load_manifest_from_source(path: Path) -> PluginManifest | None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    manifest_data = _extract_manifest(tree)
    if manifest_data is None:
        return None

    errors = validate_plugin_ast(tree, manifest_data)
    if errors:
        raise PluginValidationError("; ".join(errors))

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return build_manifest(manifest_data, path=path, digest=digest)


def build_manifest(data: dict[str, Any], *, path: Path, digest: str) -> PluginManifest:
    errors = validate_manifest_data(data)
    if errors:
        raise PluginValidationError("; ".join(errors))

    return PluginManifest(
        id=str(data["id"]),
        name=str(data["name"]),
        version=str(data["version"]),
        kind=str(data["kind"]),  # type: ignore[arg-type]
        description=str(data["description"]),
        group=str(data.get("group") or "third-party"),
        entrypoint=str(data.get("entrypoint") or "run"),
        enabled_by_default=bool(data.get("enabled_by_default", True)),
        sandbox=str(data.get("sandbox") or "process"),  # type: ignore[arg-type]
        author=str(data["author"]) if data.get("author") else None,
        capabilities=tuple(str(v) for v in data.get("capabilities", ())),
        tags=tuple(str(v) for v in data.get("tags", ())),
        consumes=tuple(str(v) for v in data.get("consumes", ())),
        produces=tuple(str(v) for v in data.get("produces", ("finding",))),
        timeout_seconds=int(data.get("timeout_seconds", 20)),
        schema_version=str(data.get("schema_version") or PLUGIN_MANIFEST_SCHEMA_VERSION),
        source_path=str(path),
        source_sha256=digest,
    )


def validate_manifest_data(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field_name in ("id", "name", "version", "kind", "description"):
        if not str(data.get(field_name, "")).strip():
            errors.append(f"PLUGIN_MANIFEST.{field_name} is required")

    plugin_id = str(data.get("id", ""))
    if plugin_id and not _PLUGIN_ID_RE.match(plugin_id):
        errors.append("PLUGIN_MANIFEST.id must be a lowercase dotted identifier")

    kind = str(data.get("kind", ""))
    if kind and kind not in _ALLOWED_KINDS:
        errors.append(f"PLUGIN_MANIFEST.kind must be one of {sorted(_ALLOWED_KINDS)}")

    sandbox = str(data.get("sandbox", "process"))
    if sandbox not in _ALLOWED_SANDBOXES:
        errors.append(f"PLUGIN_MANIFEST.sandbox must be one of {sorted(_ALLOWED_SANDBOXES)}")

    entrypoint = str(data.get("entrypoint", "run"))
    if not _ENTRYPOINT_RE.match(entrypoint):
        errors.append("PLUGIN_MANIFEST.entrypoint must be a Python function name")

    try:
        timeout = int(data.get("timeout_seconds", 20))
    except TypeError, ValueError:
        errors.append("PLUGIN_MANIFEST.timeout_seconds must be an integer")
    else:
        if timeout < 1 or timeout > 300:
            errors.append("PLUGIN_MANIFEST.timeout_seconds must be between 1 and 300")

    for list_field in ("capabilities", "tags", "consumes", "produces"):
        value = data.get(list_field, ())
        if value is not None and not isinstance(value, (list, tuple)):
            errors.append(f"PLUGIN_MANIFEST.{list_field} must be a list")

    return errors


def validate_plugin_ast(tree: ast.AST, manifest_data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    functions = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    entrypoint = str(manifest_data.get("entrypoint", "run"))
    if entrypoint not in functions:
        errors.append(f"Plugin entrypoint function '{entrypoint}' was not found")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _validate_import_root(alias.name, errors)
        elif isinstance(node, ast.ImportFrom):
            _validate_import_root(node.module or "", errors)
        elif isinstance(node, ast.Name) and node.id in _BLOCKED_NAMES:
            errors.append(f"Use of blocked builtin '{node.id}' is not allowed")
        elif isinstance(node, ast.Attribute) and node.attr in _BLOCKED_ATTRIBUTES:
            errors.append(f"Use of blocked attribute '{node.attr}' is not allowed")

    return sorted(set(errors))


def _validate_import_root(module_name: str, errors: list[str]) -> None:
    if module_name == "src.core.plugins.sdk":
        return
    root = module_name.split(".", 1)[0]
    if root not in _ALLOWED_IMPORT_ROOTS:
        errors.append(f"Import '{module_name}' is not allowed in dynamic plugins")


def _extract_manifest(tree: ast.AST) -> dict[str, Any] | None:
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "PLUGIN_MANIFEST"
            for target in node.targets
        ):
            continue
        try:
            value = _literal_manifest_value(node.value)
        except (TypeError, ValueError) as exc:
            raise PluginValidationError(
                "PLUGIN_MANIFEST must be a literal dict or manifest(...) call"
            ) from exc
        if not isinstance(value, dict):
            raise PluginValidationError("PLUGIN_MANIFEST must be a dict")
        return value
    return None


def _literal_manifest_value(node: ast.AST) -> dict[str, Any]:
    if isinstance(node, ast.Call) and _is_manifest_helper_call(node):
        return {
            keyword.arg: ast.literal_eval(keyword.value) for keyword in node.keywords if keyword.arg
        }
    value = ast.literal_eval(node)
    if not isinstance(value, dict):
        raise ValueError("manifest is not a dict")
    return value


def _is_manifest_helper_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id == "manifest"
    if isinstance(node.func, ast.Attribute):
        return node.func.attr == "manifest"
    return False
