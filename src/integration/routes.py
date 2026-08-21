"""Match HTTP method + path onto a catalog command."""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.integration.commands import CATALOG, CommandSpec, get_command
from src.integration.errors import not_found

_PARAM_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True, slots=True)
class RouteMatch:
    spec: CommandSpec
    params: dict[str, str]


def _compile(path: str) -> re.Pattern[str]:
    parts: list[str] = []
    index = 0
    for match in _PARAM_RE.finditer(path):
        parts.append(re.escape(path[index : match.start()]))
        parts.append(f"(?P<{match.group(1)}>[^/]+)")
        index = match.end()
    parts.append(re.escape(path[index:]))
    return re.compile("^" + "".join(parts) + "$")


_COMPILED: tuple[tuple[CommandSpec, re.Pattern[str]], ...] = tuple(
    (spec, _compile(spec.path)) for spec in CATALOG
)


def match_route(method: str, path: str) -> RouteMatch:
    verb = str(method or "GET").upper()
    raw = str(path or "")
    if raw.endswith("/") and raw != "/":
        raw = raw[:-1]
    # Static segments beat `{params}` so /jobs/summaries is not captured as {id}.
    ranked = sorted(
        _COMPILED,
        key=lambda item: (item[0].path.count("{"), -item[0].path.count("/")),
    )
    for spec, pattern in ranked:
        if spec.method != verb:
            continue
        found = pattern.match(raw)
        if found is None:
            continue
        return RouteMatch(spec=spec, params=found.groupdict())
    raise not_found("no console route", method=verb, path=raw)


def command_path(name: str, **params: str) -> str:
    spec = get_command(name)
    path = spec.path
    for key, value in params.items():
        path = path.replace("{" + key + "}", value)
    return path
