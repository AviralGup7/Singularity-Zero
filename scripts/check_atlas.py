#!/usr/bin/env python3
"""CI gate: flowchart.md mermaid fences, P0 syntax, port pairing."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATLAS = ROOT / "docs" / "flowchart.md"


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
    if errors:
        print("atlas check FAILED:")
        for item in errors:
            print(" -", item)
        return 1
    print(f"atlas check OK mermaid_blocks={opens}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
