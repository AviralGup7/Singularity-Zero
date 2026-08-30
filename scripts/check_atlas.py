#!/usr/bin/env python3
"""CI gate: flowchart.md mermaid fences, P0 syntax, ports, ASCII safety."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATLAS = ROOT / "docs" / "flowchart.md"

# Unicode arrows forbidden inside mermaid fences (atlas ASCII safety).
_BAD_ARROWS = ("→", "↔", "⇒", "⟶", "⟷")


def _mermaid_blocks(text: str) -> list[str]:
    return re.findall(r"```mermaid([\s\S]*?)```", text)


def main() -> int:
    text = ATLAS.read_text(encoding="utf-8")
    errors: list[str] = []
    opens = text.count("```mermaid")
    fences = text.count("```")
    if opens < 1:
        errors.append("no mermaid blocks")
    if fences % 2:
        errors.append(f"unbalanced fences mermaid={opens} all_ticks={fences}")
    if ":::for     Consume" in text or ":::for     Consume[" in text:
        errors.append("F-004 Rej/Consume declarations are merged")
    if 'Ticket["AuthorizedExecutionTicket I30' not in text:
        errors.append("F-004 Ticket node missing")
    if "PORT_F003_OUTBOX_NOTIFY_OUT" not in text or "PORT_F003_OUTBOX_NOTIFY_IN" not in text:
        errors.append("outbox notify port pair missing")
    if "PORT_F003_OUTBOX_NOTIFY_IN --> Emit" in text:
        errors.append("F-003 notify port must not independently trigger Emit")
    if "PORT_F019_BUS_IN" not in text:
        errors.append("F-019 inbound EventBus port missing")
    if "DeclaredGraph --> ProfileOverride" in text:
        errors.append("DeclaredGraph must not feed the live prune path")
    if ":::anchor" in text or ":::property" in text:
        errors.append("F-004 uses extra classDefs not in the Legend taxonomy")
    if "| **I40** |" in text:
        errors.append("I40 still in registry; use I39")
    if "Global invariants I1–I37" in text:
        errors.append("F-033 heading still I1–I37")
    # Settle verb honesty (code uses RELEASE not COMPENSATE for budget_action)
    if re.search(r"\|\s*`COMPENSATE`\s*\(Available", text):
        errors.append("settle table still uses COMPENSATE budget_action; code uses RELEASE")
    # ASCII safety inside mermaid
    for i, block in enumerate(_mermaid_blocks(text)):
        for arrow in _BAD_ARROWS:
            if arrow in block:
                errors.append(f"mermaid block {i}: forbidden unicode arrow {arrow!r}")
                break
    # Port pairing: every *_OUT should have a sibling *_IN (best-effort)
    ports = set(re.findall(r"PORT_[A-Z0-9_]+", text))
    for port in sorted(ports):
        if port.endswith("_OUT"):
            sibling = port[: -len("_OUT")] + "_IN"
            if sibling not in ports and port not in {
                # known intentionally one-sided export markers
                "PORT_EMIT_PARTIAL_ON_SHUTDOWN",
            }:
                # soft: only error if both naming conventions appear elsewhere
                if any(p.endswith("_IN") for p in ports):
                    errors.append(f"port pairing: {port} missing {sibling}")
    # dangling PORT_F003_OUTBOX_NOTIFY_IN must have an edge somewhere
    if "PORT_F003_OUTBOX_NOTIFY_IN" in text:
        if not re.search(r"PORT_F003_OUTBOX_NOTIFY_IN\s*--+>", text) and not re.search(
            r"-->\s*PORT_F003_OUTBOX_NOTIFY_IN", text
        ):
            # allow reference in prose tables without edge only if marked residual
            if "Architecture Review Residuals" not in text:
                errors.append(
                    "PORT_F003_OUTBOX_NOTIFY_IN appears without edge and no residuals section"
                )

    # Phase-2 honesty anchors
    if "raft_capabilities" not in text and "quorum-1" not in text.lower():
        errors.append("atlas missing Raft deployment honesty (quorum-1 / raft_capabilities)")
    if "evidence only" not in text.lower() and "evidence-only" not in text.lower():
        # soft: SWIM must not grant authority
        if "SWIM" in text and "grants authority" in text.lower():
            errors.append("SWIM must not be described as granting authority")

    # Phase-5: residual honesty anchors
    if "PartitionWALReplicator" not in text and "partition_wal" not in text.lower():
        errors.append("atlas missing PartitionWAL replicate honesty anchor")
    if "ConsumeExecutionTicket" not in text and "consumed_ticket" not in text.lower():
        errors.append("atlas missing ConsumeExecutionTicket / consumed_ticket anchor")
    if "optional_needs" not in text:
        errors.append("atlas missing optional_needs (P0-8)")
    if "quorum-1" not in text.lower() and "quorum 1" not in text.lower():
        errors.append("atlas missing quorum-1 production default honesty")
    # F-004/F-006 pairing labels preferred
    if "PORT_F004_RES_IN" in text and "PORT_F006_RES" in text:
        if "pairs with PORT_F006_RES" not in text and "PORT_F006_RES" in text:
            pass  # soft
    # Retired I40 already checked
    # Taxonomy: forbid inventing PORT_F033_* without F-033 section body
    f033_ports = [x for x in ports if x.startswith("PORT_F033")]
    if f033_ports and "F-033" not in text:
        errors.append(f"F-033 ports declared without F-033 section: {f033_ports}")

    if errors:
        print("atlas check FAILED:")
        for item in errors:
            print(" -", item)
        return 1
    print(f"atlas check OK mermaid_blocks={opens} ports={len(ports)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
