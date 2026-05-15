"""Analyst notes and tagging system for findings.

Provides Pydantic models for Note, Tag, FindingAnnotation,
CRUD operations, tag management, and import/export functionality.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

_DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "output"


class Tag(BaseModel):
    """Represents a tag for categorizing notes."""

    name: str = Field(..., min_length=1, max_length=64)
    description: str = Field(default="")
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class Note(BaseModel):
    """Represents an analyst note attached to a finding or cockpit element."""

    note_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    finding_id: str = Field(..., min_length=1)
    graph_node_id: str | None = Field(default=None)
    graph_edge_id: str | None = Field(default=None)
    exchange_id: str | None = Field(default=None)
    note: str = Field(..., min_length=1)
    tags: list[str] = Field(default_factory=list)
    author: str = Field(default="anonymous", min_length=1)
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class FindingAnnotation(BaseModel):
    """Links notes to a finding with metadata."""

    finding_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    notes: list[Note] = Field(default_factory=list)
    tags: list[Tag] = Field(default_factory=list)
    annotated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def add_note(self, note: Note) -> None:
        self.notes.append(note)
        self.updated_at = datetime.now(UTC).isoformat()

    def remove_note(self, note_id: str) -> bool:
        original = len(self.notes)
        self.notes = [n for n in self.notes if n.note_id != note_id]
        if len(self.notes) < original:
            self.updated_at = datetime.now(UTC).isoformat()
            return True
        return False

    def get_notes_by_tag(self, tag_name: str) -> list[Note]:
        normalized = tag_name.strip().lower()
        return [n for n in self.notes if normalized in [t.strip().lower() for t in n.tags]]

    def add_tag(self, tag: Tag) -> None:
        if not any(t.name.lower() == tag.name.lower() for t in self.tags):
            self.tags.append(tag)
            self.updated_at = datetime.now(UTC).isoformat()

    def remove_tag(self, tag_name: str) -> bool:
        original = len(self.tags)
        self.tags = [t for t in self.tags if t.name.lower() != tag_name.strip().lower()]
        if len(self.tags) < original:
            self.updated_at = datetime.now(UTC).isoformat()
            return True
        return False

    def list_tags(self) -> list[str]:
        return [t.name for t in self.tags]


def _annotations_path(output_dir: Path, target_id: str) -> Path:
    target_dir = output_dir / target_id
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir / "annotations.json"


def _load_annotations(annotations_file: Path) -> dict[str, Any]:
    if not annotations_file.exists():
        return {}
    try:
        data = json.loads(annotations_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        return {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load annotations from %s: %s", annotations_file, exc)
        return {}


def _save_annotations(annotations_file: Path, data: dict[str, Any]) -> None:
    try:
        annotations_file.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        logger.error("Failed to save annotations to %s: %s", annotations_file, exc)


def _annotation_to_dict(annotation: FindingAnnotation) -> dict[str, Any]:
    return {
        "finding_id": annotation.finding_id,
        "target_id": annotation.target_id,
        "notes": [n.model_dump() for n in annotation.notes],
        "tags": [t.model_dump() for t in annotation.tags],
        "annotated_at": annotation.annotated_at,
        "updated_at": annotation.updated_at,
    }


def _dict_to_annotation(data: dict[str, Any]) -> FindingAnnotation:
    notes = [Note(**n) for n in data.get("notes", [])]
    tags = [Tag(**t) for t in data.get("tags", [])]
    return FindingAnnotation(
        finding_id=data.get("finding_id", ""),
        target_id=data.get("target_id", ""),
        notes=notes,
        tags=tags,
        annotated_at=data.get("annotated_at", datetime.now(UTC).isoformat()),
        updated_at=data.get("updated_at", datetime.now(UTC).isoformat()),
    )


def _load_all_annotations(output_dir: Path, target_id: str) -> dict[str, FindingAnnotation]:
    annotations_file = _annotations_path(output_dir, target_id)
    raw = _load_annotations(annotations_file)
    result: dict[str, FindingAnnotation] = {}
    for finding_id, data in raw.items():
        result[finding_id] = _dict_to_annotation(data)
    return result


def _save_all_annotations(
    output_dir: Path, target_id: str, annotations: dict[str, FindingAnnotation]
) -> None:
    annotations_file = _annotations_path(output_dir, target_id)
    serialized = {fid: _annotation_to_dict(ann) for fid, ann in annotations.items()}
    _save_annotations(annotations_file, serialized)


def create_note(
    target_id: str,
    finding_id: str,
    note: str,
    tags: list[str] | None = None,
    author: str = "anonymous",
    graph_node_id: str | None = None,
    graph_edge_id: str | None = None,
    exchange_id: str | None = None,
    output_dir: Path | None = None,
) -> Note:
    """Create a new note and attach it to a finding.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        note: Note text.
        tags: Optional list of tag names.
        author: Author name.
        graph_node_id: Optional graph node ID.
        graph_edge_id: Optional graph edge ID.
        exchange_id: Optional forensic exchange ID.
        output_dir: Output directory.

    Returns:
        The created Note model instance.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)

    annotation = annotations.get(finding_id)
    if annotation is None:
        annotation = FindingAnnotation(finding_id=finding_id, target_id=target_id)
        annotations[finding_id] = annotation

    normalized_tags = [str(t).strip().lower() for t in (tags or []) if str(t).strip()]
    new_note = Note(
        finding_id=finding_id,
        graph_node_id=graph_node_id,
        graph_edge_id=graph_edge_id,
        exchange_id=exchange_id,
        note=note,
        tags=normalized_tags,
        author=author.strip() or "anonymous",
    )

    annotation.add_note(new_note)
    _save_all_annotations(base_dir, target_id, annotations)
    logger.info(
        "Created note %s for finding %s on target %s", new_note.note_id, finding_id, target_id
    )
    return new_note


def get_note(
    target_id: str,
    finding_id: str,
    note_id: str,
    output_dir: Path | None = None,
) -> Note | None:
    """Retrieve a single note by ID.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        note_id: Note identifier.
        output_dir: Output directory.

    Returns:
        Note instance or None if not found.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return None
    for n in annotation.notes:
        if n.note_id == note_id:
            return n
    return None


def get_notes(
    target_id: str,
    finding_id: str,
    output_dir: Path | None = None,
) -> list[Note]:
    """Get all notes for a specific finding.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        output_dir: Output directory.

    Returns:
        List of Note instances.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return []
    return list(annotation.notes)


def get_all_notes(
    target_id: str,
    output_dir: Path | None = None,
) -> list[Note]:
    """Get all notes across all findings for a target.

    Args:
        target_id: Target identifier.
        output_dir: Output directory.

    Returns:
        List of all Note instances.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    result: list[Note] = []
    for annotation in annotations.values():
        result.extend(annotation.notes)
    return result


def update_note(
    target_id: str,
    finding_id: str,
    note_id: str,
    note: str | None = None,
    tags: list[str] | None = None,
    graph_node_id: str | None = None,
    graph_edge_id: str | None = None,
    exchange_id: str | None = None,
    output_dir: Path | None = None,
) -> Note | None:
    """Update an existing note.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        note_id: Note identifier.
        note: New note text.
        tags: New tags list.
        graph_node_id: New graph node ID.
        graph_edge_id: New graph edge ID.
        exchange_id: New forensic exchange ID.
        output_dir: Output directory.

    Returns:
        Updated Note instance or None if not found.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return None

    for n in annotation.notes:
        if n.note_id == note_id:
            if note is not None:
                n.note = note
            if tags is not None:
                n.tags = [str(t).strip().lower() for t in tags if str(t).strip()]
            if graph_node_id is not None:
                n.graph_node_id = graph_node_id
            if graph_edge_id is not None:
                n.graph_edge_id = graph_edge_id
            if exchange_id is not None:
                n.exchange_id = exchange_id
            n.updated_at = datetime.now(UTC).isoformat()
            annotation.updated_at = datetime.now(UTC).isoformat()
            _save_all_annotations(base_dir, target_id, annotations)
            logger.info(
                "Updated note %s for finding %s on target %s", note_id, finding_id, target_id
            )
            return n

    return None


def delete_note(
    target_id: str,
    finding_id: str,
    note_id: str,
    output_dir: Path | None = None,
) -> bool:
    """Delete a note by ID.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        note_id: Note identifier.
        output_dir: Output directory.

    Returns:
        True if deleted, False otherwise.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return False

    if annotation.remove_note(note_id):
        _save_all_annotations(base_dir, target_id, annotations)
        logger.info("Deleted note %s from finding %s on target %s", note_id, finding_id, target_id)
        return True

    return False


def add_tag_to_note(
    target_id: str,
    finding_id: str,
    note_id: str,
    tag_name: str,
    output_dir: Path | None = None,
) -> Note | None:
    """Add a tag to an existing note.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        note_id: Note identifier.
        tag_name: Tag name to add.
        output_dir: Output directory.

    Returns:
        Updated Note instance or None if not found.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return None

    normalized = tag_name.strip().lower()
    for n in annotation.notes:
        if n.note_id == note_id:
            if normalized not in [t.strip().lower() for t in n.tags]:
                n.tags.append(normalized)
                n.updated_at = datetime.now(UTC).isoformat()
                annotation.updated_at = datetime.now(UTC).isoformat()
                _save_all_annotations(base_dir, target_id, annotations)
                logger.info("Added tag '%s' to note %s", normalized, note_id)
            return n

    return None


def remove_tag_from_note(
    target_id: str,
    finding_id: str,
    note_id: str,
    tag_name: str,
    output_dir: Path | None = None,
) -> Note | None:
    """Remove a tag from an existing note.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        note_id: Note identifier.
        tag_name: Tag name to remove.
        output_dir: Output directory.

    Returns:
        Updated Note instance or None if not found.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return None

    normalized = tag_name.strip().lower()
    for n in annotation.notes:
        if n.note_id == note_id:
            original = len(n.tags)
            n.tags = [t for t in n.tags if t.strip().lower() != normalized]
            if len(n.tags) < original:
                n.updated_at = datetime.now(UTC).isoformat()
                annotation.updated_at = datetime.now(UTC).isoformat()
                _save_all_annotations(base_dir, target_id, annotations)
                logger.info("Removed tag '%s' from note %s", normalized, note_id)
            return n

    return None


def list_tags_for_finding(
    target_id: str,
    finding_id: str,
    output_dir: Path | None = None,
) -> list[str]:
    """List all unique tags used in notes for a finding.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        output_dir: Output directory.

    Returns:
        Sorted list of unique tag names.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return []

    tag_set: set[str] = set()
    for n in annotation.notes:
        for t in n.tags:
            tag_set.add(t.strip().lower())
    return sorted(tag_set)


def search_notes_by_tag(
    target_id: str,
    tag_name: str,
    output_dir: Path | None = None,
) -> list[tuple[str, Note]]:
    """Search all notes across findings that contain a specific tag.

    Args:
        target_id: Target identifier.
        tag_name: Tag name to search for.
        output_dir: Output directory.

    Returns:
        List of (finding_id, Note) tuples matching the tag.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    normalized = tag_name.strip().lower()
    results: list[tuple[str, Note]] = []

    for finding_id, annotation in annotations.items():
        for n in annotation.notes:
            if normalized in [t.strip().lower() for t in n.tags]:
                results.append((finding_id, n))

    return results


def get_finding_annotation(
    target_id: str,
    finding_id: str,
    output_dir: Path | None = None,
) -> FindingAnnotation | None:
    """Get the full annotation object for a finding.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        output_dir: Output directory.

    Returns:
        FindingAnnotation instance or None if no annotations exist.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    return annotations.get(finding_id)


def add_tag_to_finding(
    target_id: str,
    finding_id: str,
    tag_name: str,
    description: str = "",
    output_dir: Path | None = None,
) -> FindingAnnotation | None:
    """Add a tag at the finding annotation level.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        tag_name: Tag name.
        description: Tag description.
        output_dir: Output directory.

    Returns:
        Updated FindingAnnotation or None if not found.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)

    annotation = annotations.get(finding_id)
    if annotation is None:
        annotation = FindingAnnotation(finding_id=finding_id, target_id=target_id)
        annotations[finding_id] = annotation

    tag = Tag(name=tag_name.strip(), description=description.strip())
    annotation.add_tag(tag)
    _save_all_annotations(base_dir, target_id, annotations)
    logger.info("Added tag '%s' to finding annotation %s", tag_name, finding_id)
    return annotation


def remove_tag_from_finding(
    target_id: str,
    finding_id: str,
    tag_name: str,
    output_dir: Path | None = None,
) -> FindingAnnotation | None:
    """Remove a tag from the finding annotation level.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        tag_name: Tag name to remove.
        output_dir: Output directory.

    Returns:
        Updated FindingAnnotation or None if not found.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return None

    if annotation.remove_tag(tag_name):
        _save_all_annotations(base_dir, target_id, annotations)
        logger.info("Removed tag '%s' from finding annotation %s", tag_name, finding_id)
        return annotation

    return None


def list_finding_tags(
    target_id: str,
    finding_id: str,
    output_dir: Path | None = None,
) -> list[Tag]:
    """List all tags at the finding annotation level.

    Args:
        target_id: Target identifier.
        finding_id: Finding identifier.
        output_dir: Output directory.

    Returns:
        List of Tag instances.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    annotation = annotations.get(finding_id)
    if annotation is None:
        return []
    return list(annotation.tags)


def export_annotations(
    target_id: str,
    output_dir: Path | None = None,
    export_path: Path | None = None,
) -> str:
    """Export all annotations for a target as JSON string.

    Args:
        target_id: Target identifier.
        output_dir: Output directory for source annotations.
        export_path: Optional file path to write the export.

    Returns:
        JSON string of all annotations.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR
    annotations = _load_all_annotations(base_dir, target_id)
    serialized = {fid: _annotation_to_dict(ann) for fid, ann in annotations.items()}
    json_str = json.dumps(serialized, ensure_ascii=False, indent=2)

    if export_path is not None:
        try:
            export_path.parent.mkdir(parents=True, exist_ok=True)
            export_path.write_text(json_str, encoding="utf-8")
            logger.info("Exported annotations for target %s to %s", target_id, export_path)
        except OSError as exc:
            logger.error("Failed to export annotations to %s: %s", export_path, exc)

    return json_str


def import_annotations(
    target_id: str,
    json_data: str,
    output_dir: Path | None = None,
    merge: bool = True,
) -> dict[str, FindingAnnotation]:
    """Import annotations from a JSON string.

    Args:
        target_id: Target identifier.
        json_data: JSON string of annotations.
        output_dir: Output directory.
        merge: If True, merge with existing annotations; if False, replace.

    Returns:
        Dictionary of finding_id to FindingAnnotation.
    """
    base_dir = output_dir or _DEFAULT_OUTPUT_DIR

    try:
        raw = json.loads(json_data)
        if not isinstance(raw, dict):
            raise ValueError("JSON data must be an object")
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error("Failed to parse import JSON: %s", exc)
        return {}

    imported: dict[str, FindingAnnotation] = {}
    for finding_id, data in raw.items():
        annotation = _dict_to_annotation(data)
        annotation.target_id = target_id
        imported[finding_id] = annotation

    if merge:
        existing = _load_all_annotations(base_dir, target_id)
        for fid, ann in imported.items():
            if fid in existing:
                existing_ann = existing[fid]
                for note in ann.notes:
                    if not any(n.note_id == note.note_id for n in existing_ann.notes):
                        existing_ann.add_note(note)
                for tag in ann.tags:
                    existing_ann.add_tag(tag)
                imported[fid] = existing_ann
            else:
                existing[fid] = ann
        imported = existing

    _save_all_annotations(base_dir, target_id, imported)
    logger.info("Imported %d finding annotations for target %s", len(imported), target_id)
    return imported


def get_notes_for_finding(
    target_id: str,
    finding_id: str,
    output_dir: Path | None = None,
) -> list[Note]:
    """Alias for get_notes to support alternate naming."""
    return get_notes(target_id, finding_id, output_dir)


__all__ = [
    "Tag",
    "Note",
    "FindingAnnotation",
    "create_note",
    "get_note",
    "get_notes",
    "get_all_notes",
    "update_note",
    "delete_note",
    "add_tag_to_note",
    "remove_tag_from_note",
    "list_tags_for_finding",
    "search_notes_by_tag",
    "get_finding_annotation",
    "add_tag_to_finding",
    "remove_tag_from_finding",
    "list_finding_tags",
    "export_annotations",
    "import_annotations",
    "get_notes_for_finding",
]
