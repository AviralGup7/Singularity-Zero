"""Unit tests for src.analysis.active.injection._context_detector."""

import unittest

import pytest

from src.analysis.active.injection._context_detector import (
    ContextDetector,
    ReflectionContext,
)


@pytest.mark.unit
class TestContextDetectorBasic(unittest.TestCase):
    def test_empty_html_no_reflections(self) -> None:
        detector = ContextDetector("")
        self.assertEqual(detector.detect_all(), [])
        self.assertEqual(detector.count_reflections(), 0)
        self.assertFalse(detector.has_reflection())

    def test_marker_not_in_html(self) -> None:
        detector = ContextDetector("<html><body>Hello</body></html>")
        self.assertEqual(detector.detect_all(), [])

    def test_total_reflections_count(self) -> None:
        body = "<p>v3dm0s appears v3dm0s twice</p>"
        detector = ContextDetector(body)
        self.assertEqual(detector.count_reflections(), 2)
        self.assertEqual(detector.total_reflections, 2)
        self.assertTrue(detector.has_reflection())


@pytest.mark.unit
class TestContextDetection(unittest.TestCase):
    def test_html_context(self) -> None:
        body = "<html><body>v3dm0s</body></html>"
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0].context, "html")

    def test_attribute_context(self) -> None:
        body = '<div class="v3dm0s">content</div>'
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0].context, "attribute")
        self.assertEqual(contexts[0].attribute_name, "class")
        self.assertEqual(contexts[0].quote_style, '"')

    def test_script_context(self) -> None:
        body = "<script>var x = 'v3dm0s';</script>"
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0].context, "script")
        self.assertEqual(contexts[0].tag, "script")

    def test_comment_context(self) -> None:
        body = "<html><!-- v3dm0s comment --></html>"
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        # Should be detected as comment
        comment_ctx = [c for c in contexts if c.context == "comment"]
        self.assertGreaterEqual(len(comment_ctx), 1)

    def test_dead_context_in_title(self) -> None:
        body = "<html><title>v3dm0s</title></html>"
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        # The reflection inside <title> is dead
        dead_ctx = [c for c in contexts if c.context == "dead"]
        self.assertGreaterEqual(len(dead_ctx), 1)
        self.assertEqual(dead_ctx[0].tag, "title")

    def test_dead_context_in_textarea(self) -> None:
        body = "<html><textarea>v3dm0s</textarea></html>"
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        dead_ctx = [c for c in contexts if c.context == "dead"]
        self.assertGreaterEqual(len(dead_ctx), 1)
        self.assertEqual(dead_ctx[0].tag, "textarea")

    def test_dead_context_in_style(self) -> None:
        body = "<html><style>v3dm0s</style></html>"
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        dead_ctx = [c for c in contexts if c.context == "dead"]
        self.assertGreaterEqual(len(dead_ctx), 1)


@pytest.mark.unit
class TestCustomMarker(unittest.TestCase):
    def test_default_marker_finds_reflection(self) -> None:
        # The default marker "v3dm0s" is the only one the internal regexes
        # are designed to detect end-to-end.
        body = "<html>v3dm0s appears here</html>"
        detector = ContextDetector(body, marker="v3dm0s")
        contexts = detector.detect_all()
        self.assertGreaterEqual(len(contexts), 1)
        self.assertEqual(contexts[0].context, "html")

    def test_default_marker_in_attribute(self) -> None:
        body = '<div class="v3dm0s">content</div>'
        detector = ContextDetector(body, marker="v3dm0s")
        contexts = detector.detect_all()
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0].context, "attribute")
        self.assertEqual(contexts[0].attribute_name, "class")

    def test_count_with_explicit_marker(self) -> None:
        body = "<html>v3dm0s appears v3dm0s twice</html>"
        detector = ContextDetector(body, marker="v3dm0s")
        self.assertEqual(detector.count_reflections(marker="v3dm0s"), 2)

    def test_has_reflection_uses_explicit_marker(self) -> None:
        body = "<html>v3dm0s appears</html>"
        detector = ContextDetector(body, marker="v3dm0s")
        self.assertTrue(detector.has_reflection(marker="v3dm0s"))
        self.assertFalse(detector.has_reflection(marker="nonexistent"))


@pytest.mark.unit
class TestReflectionContextDataclass(unittest.TestCase):
    def test_minimal_construction(self) -> None:
        ctx = ReflectionContext(position=10, context="html")
        self.assertEqual(ctx.position, 10)
        self.assertEqual(ctx.context, "html")
        self.assertIsNone(ctx.tag)
        self.assertIsNone(ctx.attribute_name)
        self.assertIsNone(ctx.attribute_value_before_marker)
        self.assertIsNone(ctx.quote_style)

    def test_full_construction(self) -> None:
        ctx = ReflectionContext(
            position=42,
            context="attribute",
            tag="div",
            attribute_name="class",
            attribute_value_before_marker="prefix",
            quote_style='"',
        )
        self.assertEqual(ctx.tag, "div")
        self.assertEqual(ctx.attribute_name, "class")
        self.assertEqual(ctx.attribute_value_before_marker, "prefix")
        self.assertEqual(ctx.quote_style, '"')

    def test_frozen(self) -> None:
        ctx = ReflectionContext(position=0, context="html")
        with self.assertRaises(Exception):
            ctx.position = 5  # type: ignore[misc]


@pytest.mark.unit
class TestContextPriority(unittest.TestCase):
    def test_script_takes_priority_over_attribute(self) -> None:
        # Marker is inside script AND attribute (should classify as script)
        body = '<div title="x"><script>v3dm0s</script></div>'
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        script_ctx = [c for c in contexts if c.context == "script"]
        self.assertGreaterEqual(len(script_ctx), 1)

    def test_sorted_by_position(self) -> None:
        body = "<p>v3dm0s</p><p>v3dm0s</p><p>v3dm0s</p>"
        detector = ContextDetector(body)
        contexts = detector.detect_all()
        positions = [c.position for c in contexts]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
