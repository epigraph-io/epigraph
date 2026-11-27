"""Convention pins: incident-driven passages pinned to the section they govern.

A convention line written because of an incident (a backlog item, an issue)
is only as durable as the next edit of the file it lives in. A pin names the
passage, the section it must stay inside, and the incident that motivated it,
so an edit that drops or moves the rule fails `test_convention_pins.py`
instead of passing review silently.

Matching is whitespace-normalized (every run of whitespace is one space), so a
re-wrapped paragraph keeps its pins. A section runs from the first occurrence
of `section_start` to the first occurrence of `section_end` after it.

Adding a pin: when you add or change a convention line because of an incident,
add a `Pin` below naming the incident (an 8-hex backlog prefix, or `#NNN` for
a GitHub issue or PR). Pick a needle that states the rule, not its wording
around it, and keep it to one line in a Rust doc comment (the `///` prefix of
the next line would be part of a wrapped needle).

Standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# An 8-hex backlog prefix, or a GitHub issue / PR number.
INCIDENT_ID = re.compile(r"^(?:[0-9a-f]{8}|#[0-9]+)$")


@dataclass(frozen=True)
class Pin:
    id: str
    file: str
    section_start: str
    section_end: str
    needle: str
    incident: str


def normalize(text: str) -> str:
    """Collapse every run of whitespace to one space."""
    return " ".join(text.split())


def section(text: str, start: str, end: str) -> str | None:
    """The normalized text from `start` up to (not including) `end`, or None."""
    body = normalize(text)
    s = normalize(start)
    i = body.find(s)
    if i < 0:
        return None
    j = body.find(normalize(end), i + len(s))
    if j < 0:
        return None
    return body[i:j]


def check(pin: Pin, text: str) -> str | None:
    """None when `pin` holds on `text`, else the reason it does not."""
    body = section(text, pin.section_start, pin.section_end)
    if body is None:
        return (
            f"{pin.id}: section {pin.section_start!r} .. {pin.section_end!r} "
            f"not found in {pin.file}"
        )
    if normalize(pin.needle) not in body:
        return (
            f"{pin.id}: {pin.needle!r} is not inside section {pin.section_start!r} "
            f"of {pin.file} (incident {pin.incident})"
        )
    return None


def delete_needle(text: str, needle: str) -> str:
    """`text`, normalized, with every occurrence of `needle` removed."""
    return normalize(text).replace(normalize(needle), "")


def read(pin: Pin) -> str:
    return (REPO / pin.file).read_text(encoding="utf-8")


PINS: tuple[Pin, ...] = (
    # --- CLAUDE.md, "Retiring backlog items" -------------------------------
    Pin(
        id="backlog-resolved-label-gated-on-every-transport",
        file="CLAUDE.md",
        section_start="## Retiring backlog items",
        section_end="## Schema, migrations, claim mechanics",
        needle=(
            "apply `resolve_backlog_item`'s `require_owner_or_admin` check when a "
            "call adds or removes it, on EVERY transport"
        ),
        incident="#374",
    ),
    Pin(
        id="backlog-retire-http-whole-label-mutation",
        file="CLAUDE.md",
        section_start="## Retiring backlog items",
        section_end="## Schema, migrations, claim mechanics",
        needle="Over HTTP the WHOLE label mutation needs that ownership, whatever the labels",
        incident="#374",
    ),
    # --- CLAUDE.md, "Belief values" (and the TruthValue doc pointing at it) -
    Pin(
        id="belief-compare-with-tolerance",
        file="CLAUDE.md",
        section_start="## Belief values: f64, reproducible per platform only",
        section_end="## Status claims bypass the novelty gate",
        needle="compare a belief with an absolute tolerance (e.g. `1e-9`)",
        incident="de039f69",
    ),
    Pin(
        id="belief-never-hashed-or-signed",
        file="CLAUDE.md",
        section_start="## Belief values: f64, reproducible per platform only",
        section_end="## Status claims bypass the novelty gate",
        needle="**Never hash or sign a computed belief.**",
        incident="de039f69",
    ),
    Pin(
        id="truth-value-doc-points-at-belief-convention",
        file="crates/epigraph-core/src/truth.rs",
        section_start="/// A truth value bounded to [0.0, 1.0]",
        section_end="pub struct TruthValue(f64);",
        needle='`CLAUDE.md`, "Belief values: f64, reproducible per platform only"',
        incident="de039f69",
    ),
    # --- Backlog evidence tier (docs/conventions, pointed at from CLAUDE.md) -
    Pin(
        id="backlog-candidate-label-defined",
        file="docs/conventions/backlog-retirement.md",
        section_start="## Filing backlog items: evidence tier",
        section_end="## Retiring a backlog item",
        needle=(
            "Label an item `backlog-candidate` (alongside `backlog`) when its only "
            "support is static reading"
        ),
        incident="d543f045",
    ),
    Pin(
        id="backlog-candidate-structural-vs-behavioural",
        file="docs/conventions/backlog-retirement.md",
        section_start="## Filing backlog items: evidence tier",
        section_end="## Retiring a backlog item",
        needle=(
            "*Behavioural* claims (a wrong result, a race, a refusal) need an "
            "executed test, a reproduced call, or a read"
        ),
        incident="d543f045",
    ),
    Pin(
        id="backlog-candidate-removed-by-re-measurer",
        file="docs/conventions/backlog-retirement.md",
        section_start="## Filing backlog items: evidence tier",
        section_end="## Retiring a backlog item",
        needle="**The re-measurer removes `backlog-candidate`**, citing the evidence",
        incident="d543f045",
    ),
    Pin(
        id="backlog-candidate-never-closed-unmeasured",
        file="docs/conventions/backlog-retirement.md",
        section_start="## Filing backlog items: evidence tier",
        section_end="## Retiring a backlog item",
        needle="**A candidate is never closed for being unmeasured.**",
        incident="d543f045",
    ),
    Pin(
        id="claude-md-points-at-evidence-tier",
        file="CLAUDE.md",
        section_start="## Retiring backlog items",
        section_end="## Schema, migrations, claim mechanics",
        needle=(
            "`docs/conventions/backlog-retirement.md`, \"Filing backlog items: "
            "evidence tier\""
        ),
        incident="d543f045",
    ),
    # --- Per-table retirement vocabulary, linked from both backlog docs -----
    Pin(
        id="backlog-retirement-links-no-longer-in-force",
        file="docs/conventions/backlog-retirement.md",
        section_start="## Retiring a backlog item",
        section_end="## Who may retire an item",
        needle="`docs/conventions/no-longer-in-force.md`",
        incident="64eeca4e",
    ),
    Pin(
        id="claude-md-links-no-longer-in-force",
        file="CLAUDE.md",
        section_start="## Retiring backlog items",
        section_end="## Schema, migrations, claim mechanics",
        needle="`docs/conventions/no-longer-in-force.md`",
        incident="64eeca4e",
    ),
    # --- CLAUDE.md, "Test database" ----------------------------------------
    Pin(
        id="test-db-fresh-and-migrated-from-empty",
        file="CLAUDE.md",
        section_start="## Test database",
        section_end="## Workflow",
        needle=(
            "create a FRESH database whose name ends in `_test` and migrate it "
            "from empty"
        ),
        incident="acffb2c4",
    ),
    # --- CLAUDE.md, "Adding HTTP routes from a downstream product" ---------
    Pin(
        id="no-first-party-route-under-ext",
        file="CLAUDE.md",
        section_start="## Adding HTTP routes from a downstream product",
        section_end="## Retiring backlog items",
        needle="Never register a first-party route under `/api/v1/ext`",
        incident="#481",
    ),
)
