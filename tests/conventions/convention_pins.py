"""Convention pins: incident-driven passages pinned to the section they govern.

A convention line written because of an incident (a backlog item, an issue)
is only as durable as the next edit of the file it lives in. A pin names the
passage, the section it must stay inside, and the incident that motivated it,
so an edit that drops or moves the rule fails `test_convention_pins.py`.
That suite runs in CI's `plan` job, whose unittest step blocks the run on
every pull request (`.github/scripts/tests/test_conventions.py` collects it).

Sections:

- `section_end=None` (Markdown): the section is the heading line equal to
  `section_start` and everything up to the next heading of the same or a
  higher level, outside code fences. A heading inserted above the needle, or
  a renamed neighbouring section, cannot silently widen or break the pin.
- `section_end="..."` (source files, e.g. a Rust doc comment): the section
  runs from the first occurrence of `section_start` to the first occurrence of
  `section_end` after it.

Matching is whitespace-tolerant (every run of whitespace is one space), so a
re-wrapped paragraph keeps its pins.

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

HEADING = re.compile(r"^(#{1,6})[ \t]+(.*?)[ \t]*$")
FENCE = re.compile(r"^\s*(```|~~~)")


@dataclass(frozen=True)
class Pin:
    id: str
    file: str
    section_start: str
    section_end: str | None
    needle: str
    incident: str


def normalize(text: str) -> str:
    """Collapse every run of whitespace to one space."""
    return " ".join(text.split())


def pattern(phrase: str) -> re.Pattern[str]:
    """`phrase` as a regex that matches across any run of whitespace."""
    return re.compile(r"\s+".join(re.escape(w) for w in phrase.split()))


def headings(text: str) -> list[tuple[int, int, str]]:
    """(offset, level, title) of every Markdown heading outside code fences."""
    out = []
    offset = 0
    fenced = False
    for line in text.splitlines(keepends=True):
        if FENCE.match(line):
            fenced = not fenced
        elif not fenced:
            m = HEADING.match(line.rstrip("\r\n"))
            if m:
                out.append((offset, len(m.group(1)), m.group(2)))
        offset += len(line)
    return out


def section_span(text: str, start: str, end: str | None) -> tuple[int, int] | None:
    """The [i, j) offsets of the section in `text`, or None when it is absent."""
    if end is None:
        want = HEADING.match(start.strip())
        if want is None:
            raise ValueError(f"section_end=None needs a Markdown heading, not {start!r}")
        level, title = len(want.group(1)), normalize(want.group(2))
        found = headings(text)
        for k, (i, lvl, t) in enumerate(found):
            if lvl == level and normalize(t) == title:
                j = next((o for o, l2, _ in found[k + 1 :] if l2 <= level), len(text))
                return i, j
        return None
    s = pattern(start).search(text)
    if s is None:
        return None
    e = pattern(end).search(text, s.end())
    if e is None:
        return None
    return s.start(), e.start()


def section(text: str, start: str, end: str | None) -> str | None:
    """The normalized text of the section, or None when it is absent."""
    span = section_span(text, start, end)
    return None if span is None else normalize(text[span[0] : span[1]])


def check(pin: Pin, text: str) -> str | None:
    """None when `pin` holds on `text`, else the reason it does not."""
    body = section(text, pin.section_start, pin.section_end)
    if body is None:
        return (
            f"{pin.id}: section {pin.section_start!r} .. {pin.section_end or 'next heading'!r} "
            f"not found in {pin.file}"
        )
    if normalize(pin.needle) not in body:
        return (
            f"{pin.id}: {pin.needle!r} is not inside section {pin.section_start!r} "
            f"of {pin.file} (incident {pin.incident})"
        )
    return None


def delete_needle(text: str, needle: str) -> str:
    """`text` with every occurrence of `needle` removed; line breaks elsewhere kept."""
    return pattern(needle).sub("", text)


def read(pin: Pin) -> str:
    return (REPO / pin.file).read_text(encoding="utf-8")


PINS: tuple[Pin, ...] = (
    # --- CLAUDE.md, "Retiring backlog items" -------------------------------
    Pin(
        id="backlog-resolved-label-gated-on-every-transport",
        file="CLAUDE.md",
        section_start="## Retiring backlog items",
        section_end=None,
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
        section_end=None,
        needle="Over HTTP the WHOLE label mutation needs that ownership, whatever the labels",
        incident="#374",
    ),
    # --- CLAUDE.md, "Belief values" (and the TruthValue doc pointing at it) -
    Pin(
        id="belief-compare-with-tolerance",
        file="CLAUDE.md",
        section_start="## Belief values: f64, reproducible per platform only",
        section_end=None,
        needle="compare a belief with an absolute tolerance (e.g. `1e-9`)",
        incident="de039f69",
    ),
    Pin(
        id="belief-unordered-aggregates-are-defects",
        file="CLAUDE.md",
        section_start="## Belief values: f64, reproducible per platform only",
        section_end=None,
        needle="A new fold must fix its order; an existing unordered one is a defect to file",
        incident="de039f69",
    ),
    Pin(
        id="belief-never-hashed-or-signed",
        file="CLAUDE.md",
        section_start="## Belief values: f64, reproducible per platform only",
        section_end=None,
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
        section_end=None,
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
        section_end=None,
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
        section_end=None,
        needle="**The re-measurer removes `backlog-candidate`**, citing the evidence",
        incident="d543f045",
    ),
    Pin(
        id="backlog-candidate-evidence-goes-in-patch-claim",
        file="docs/conventions/backlog-retirement.md",
        section_start="## Filing backlog items: evidence tier",
        section_end=None,
        needle="use one `patch_claim` call that both removes the label",
        incident="d543f045",
    ),
    Pin(
        id="backlog-candidate-never-closed-unmeasured",
        file="docs/conventions/backlog-retirement.md",
        section_start="## Filing backlog items: evidence tier",
        section_end=None,
        needle="**A candidate is never closed for being unmeasured.**",
        incident="d543f045",
    ),
    Pin(
        id="claude-md-points-at-evidence-tier",
        file="CLAUDE.md",
        section_start="## Retiring backlog items",
        section_end=None,
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
        section_end=None,
        needle="`docs/conventions/no-longer-in-force.md`",
        incident="64eeca4e",
    ),
    Pin(
        id="claude-md-links-no-longer-in-force",
        file="CLAUDE.md",
        section_start="## Retiring backlog items",
        section_end=None,
        needle="`docs/conventions/no-longer-in-force.md`",
        incident="64eeca4e",
    ),
    # --- The match-candidate provenance note, linked from the code it covers -
    Pin(
        id="decide-match-candidate-doc-links-provenance-note",
        file="crates/epigraph-mcp/src/tools/matching.rs",
        section_start="/// Promote or reject a `pending` match candidate",
        section_end="pub async fn decide_match_candidate(",
        needle="`docs/architecture/match-candidate-edge-provenance.md`",
        incident="c8f16097",
    ),
    Pin(
        id="retire-match-candidate-doc-links-provenance-note",
        file="crates/epigraph-mcp/src/tools/matching.rs",
        section_start="/// Retire a promoted match candidate:",
        section_end="pub async fn retire_match_candidate(",
        needle="`docs/architecture/match-candidate-edge-provenance.md`",
        incident="c8f16097",
    ),
    Pin(
        id="match-candidate-repo-retire-doc-links-provenance-note",
        file="crates/epigraph-db/src/repos/match_candidate.rs",
        section_start="/// Retract a candidate's promotion:",
        section_end="pub async fn retire(&self",
        needle="`docs/architecture/match-candidate-edge-provenance.md`",
        incident="c8f16097",
    ),
    # --- CLAUDE.md, "Test database" ----------------------------------------
    Pin(
        id="test-db-fresh-and-migrated-from-empty",
        file="CLAUDE.md",
        section_start="## Test database",
        section_end=None,
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
        section_end=None,
        needle="Never register a first-party route under `/api/v1/ext`",
        incident="#481",
    ),
    # --- CLAUDE.md, "Convention pins": this rule pins itself ---------------
    Pin(
        id="incident-convention-line-gets-a-pin",
        file="CLAUDE.md",
        section_start="## Convention pins",
        section_end=None,
        needle=(
            "A convention line written because of an incident (a backlog item, "
            "an issue, a PR) gets a pin in the same change"
        ),
        incident="4caaec8e",
    ),
    Pin(
        id="convention-pins-names-this-registry",
        file="CLAUDE.md",
        section_start="## Convention pins",
        section_end=None,
        needle="a `Pin` in `tests/conventions/convention_pins.py`",
        incident="4caaec8e",
    ),
    Pin(
        id="convention-pins-names-the-prompt-registry",
        file="CLAUDE.md",
        section_start="## Convention pins",
        section_end=None,
        needle="gets a `content_pins` entry in that repository's registry",
        incident="4caaec8e",
    ),
    # --- The conjunct screen's one gated refusal (atomicity.rs, CLAUDE.md) ---
    Pin(
        id="atomicity-module-doc-names-the-gated-refusal",
        file="crates/epigraph-core/src/atomicity.rs",
        section_start="//! The atomicity heuristic: is a claim already one atomic proposition?",
        section_end="pub const ATOMIC_MAX_CHARS",
        needle="**The screen refuses a write in one case only** (backlog `40cdb432`):",
        incident="40cdb432",
    ),
    Pin(
        id="conjunct-screen-struct-doc-names-the-gated-refusal",
        file="crates/epigraph-core/src/atomicity.rs",
        section_start="/// What [`conjunct_screen`] counted in one claim's text.",
        section_end="pub struct ConjunctScreen {",
        needle="refuses nothing except under `EPIGRAPH_CONTRADICT_COMPOUND_GUARD=refuse`",
        incident="40cdb432",
    ),
    Pin(
        id="conjunct-screen-fn-doc-says-why-errors-are-accepted",
        file="crates/epigraph-core/src/atomicity.rs",
        section_start="/// Estimate how many logically independent assertions `text` makes.",
        section_end="pub fn conjunct_screen(",
        needle="refusal is opt-in, off by default, and narrow (see the module doc)",
        incident="40cdb432",
    ),
    Pin(
        id="claude-md-belief-modes-names-the-gated-refusal",
        file="CLAUDE.md",
        section_start="## Belief modes",
        section_end=None,
        needle=(
            "under `EPIGRAPH_CONTRADICT_COMPOUND_GUARD=refuse` a `contradicts` or "
            "`refutes` edge onto a target that screens compound"
        ),
        incident="40cdb432",
    ),
    # --- PR body freshness and first-parent bisect -------------------------
    Pin(
        id="pr-template-body-matches-final-commits",
        file=".github/pull_request_template.md",
        section_start="## Checklist",
        section_end=None,
        needle=(
            "After each review round, the PR body was updated to match the "
            "final commits (no stale claims)"
        ),
        incident="e0a1cce5",
    ),
    Pin(
        id="bisect-main-with-first-parent",
        file="docs/conventions/git-history.md",
        section_start="## Bisecting main",
        section_end=None,
        needle="bisect `main` with `git bisect start --first-parent`",
        incident="e0a1cce5",
    ),
    # --- The MCP screen tool's description names the gated refusal ---------
    Pin(
        id="screen-claim-atomicity-description-names-the-gated-refusal",
        file="crates/epigraph-mcp/src/server.rs",
        section_start='description = "Screen claims for compound content by id',
        section_end="async fn screen_claim_atomicity(",
        needle=(
            "only the opt-in compound-contradiction guard (see link_epistemic) "
            "refuses on it"
        ),
        incident="40cdb432",
    ),
)
