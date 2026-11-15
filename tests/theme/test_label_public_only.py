"""Stored theme and cluster labels quote PUBLIC members only (backlog 157aae7b).

A stored label is not viewer-derived: anyone who can read one member of a theme
reads its label and description. So a label built from a group-private member's
text publishes wording only that group may read. Each test seeds a public member
and group-private members of an ordinary team (no intake configured, so
theme_lib.not_intake_owned excludes nothing) and checks the private text never
reaches the sampler, the LLM prompt, the operator, or the stored label, while the
public text does.

One test per path from member text to a stored label
(theme_lib.public_label_source names them), plus the placeholder a theme with no
public member gets from label_themes_llm.main.
"""
import sys
import uuid

import numpy as np

from scripts import cluster_claims as C
from scripts import evidential_clustering as E
from scripts import label_themes_llm as L
from scripts import refine_clusters as R
from tests.theme.conftest import TEST_DSN, make_embedding
from tests.theme.test_label_excludes_intake import (
    PUBLIC_TEXT,
    REFINE_RUN,
    _claim,
    _group,
    _place_in_cluster_0,
    _refine_members,
    _split,
)

PRIVATE_TEXT = "public-only-rule group-private member walrus-opal"
LEAKED_LABEL = "Walrus opal team secrets"
LEAKED_DESCRIPTION = "Summarises the walrus-opal team's private claims."


def _private(cur, agent_id, group, content, theme_id=None, seed=3):
    return _claim(cur, agent_id, content, theme_id=theme_id, owner=group, seed=seed,
                  visibility="group")


def _theme(cur, label, description=""):
    cur.execute(
        "INSERT INTO claim_themes (label, description, claim_count, centroid) "
        "VALUES (%s, %s, 2, %s::vector) RETURNING id",
        (label, description, make_embedding(3)),
    )
    return cur.fetchone()[0]


def _cleanup(db, ids, group):
    db.rollback()
    with db.cursor() as cur:
        cur.execute("DELETE FROM cluster_labels")
        cur.execute("DELETE FROM claim_clusters")
        cur.execute("UPDATE claims SET theme_id = NULL WHERE id::text = ANY(%s)", (ids,))
        cur.execute("DELETE FROM claim_themes")
        cur.execute("DELETE FROM claims WHERE id::text = ANY(%s)", (ids,))
        cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
        cur.execute("DELETE FROM groups WHERE id = %s", (group,))
    db.commit()


def test_the_theme_label_sample_reads_public_members_only(db, seed_agent):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        theme = _theme(cur, "auto-1")
        _claim(cur, seed_agent, PUBLIC_TEXT, theme_id=theme)
        _private(cur, seed_agent, group, PRIVATE_TEXT, theme_id=theme)
        cur.execute("SELECT count(*) FROM bug_report_intake_settings")
        assert cur.fetchone()[0] == 0  # the intake conjunct excludes nothing here

    [t] = [t for t in L.load_themes_with_samples(db) if t["id"] == str(theme)]
    assert [s["content"] for s in t["samples"]] == [PUBLIC_TEXT]
    db.rollback()  # nothing above was committed


def _run_labeller(monkeypatch, *extra):
    """label_themes_llm.main against the test DB, with the Claude CLI replaced by
    a recorder that answers a fixed label. Returns the prompts it was sent."""
    prompts = []

    def fake_cli(prompt, result_path, cwd, timeout=120):
        prompts.append(prompt)
        return {"label": "LLM label", "description": "LLM description"}

    monkeypatch.setattr(L, "call_claude_cli", fake_cli)
    monkeypatch.delenv("MAINTENANCE_DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["label_themes_llm.py", "--database-url", TEST_DSN, *extra])
    L.main()
    return prompts


def _stored(db, theme):
    with db.cursor() as cur:
        cur.execute("SELECT label, description FROM claim_themes WHERE id = %s", (theme,))
        return cur.fetchone()


def test_a_theme_with_no_public_member_gets_a_placeholder_not_an_llm_label(
    db, seed_agent, monkeypatch
):
    """The data-repair run (--relabel-all) replaces a label already built from
    private text with a placeholder, without sending that text to the LLM; a
    theme with a public member is still labelled from it."""
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        private_only = _theme(cur, LEAKED_LABEL, LEAKED_DESCRIPTION)
        mixed = _theme(cur, "auto-2")
        ids = [
            _private(cur, seed_agent, group, f"{PRIVATE_TEXT} 1", theme_id=private_only),
            _private(cur, seed_agent, group, f"{PRIVATE_TEXT} 2", theme_id=private_only),
            _claim(cur, seed_agent, PUBLIC_TEXT, theme_id=mixed),
            _private(cur, seed_agent, group, f"{PRIVATE_TEXT} 3", theme_id=mixed),
        ]
    db.commit()
    try:
        # --dry-run writes nothing, not even the placeholder.
        assert _run_labeller(monkeypatch, "--relabel-all", "--dry-run") == []
        db.rollback()
        assert _stored(db, private_only) == (LEAKED_LABEL, LEAKED_DESCRIPTION)

        prompts = _run_labeller(monkeypatch, "--relabel-all")
        db.rollback()
        # Exactly one LLM call (the mixed theme), quoting only the public member.
        assert len(prompts) == 1, prompts
        assert PUBLIC_TEXT in prompts[0]
        assert not any("walrus-opal" in p for p in prompts), prompts
        assert _stored(db, mixed) == ("LLM label", "LLM description")

        label, description = _stored(db, private_only)
        assert label == L.NO_PUBLIC_MEMBER_LABEL
        assert L.is_placeholder_label(label)  # relabelled once a public member joins
        assert description == ""
        assert "walrus" not in (label + description).lower()
    finally:
        _cleanup(db, ids, group)


def test_cluster_labels_quote_public_members_only(db, seed_agent):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        ids = [
            _claim(cur, seed_agent, PUBLIC_TEXT),
            _private(cur, seed_agent, group, PRIVATE_TEXT),
        ]
    db.commit()
    try:
        reduced = np.zeros((2, 2), dtype=np.float32)
        labels = np.zeros(2, dtype=int)
        centroids = np.zeros((1, 2), dtype=np.float32)
        beliefs = {
            cid: {0: {"belief": 0.9, "plausibility": 0.95, "ignorance": 0.05}} for cid in ids
        }
        writers = (
            lambda run_id: C.label_clusters(db, ids, reduced, labels, centroids, 1, run_id),
            lambda run_id: E.store_results(db, ids, beliefs, {}, 1, {}, {}, run_id),
        )
        for write in writers:
            run_id = str(uuid.uuid4())
            write(run_id)
            with db.cursor() as cur:
                cur.execute(
                    "SELECT label FROM cluster_labels WHERE cluster_run_id = %s", (run_id,)
                )
                got = cur.fetchone()[0]
            assert PUBLIC_TEXT in got, got
            assert PRIVATE_TEXT not in got, got
    finally:
        _cleanup(db, ids, group)


def test_auto_refine_labels_quote_public_members_only(db, seed_agent, monkeypatch):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        public, private = _refine_members(cur, seed_agent, group, text=PRIVATE_TEXT,
                                          visibility="group")
    db.commit()
    ids = public + private
    asked = []

    def labeller(samples, idx):
        asked.append(list(samples))
        return f"LBL {samples[0]}" if samples else ""

    monkeypatch.setattr(R, "llm_label_subcluster", labeller)
    try:
        _place_in_cluster_0(db, ids)
        result = R.auto_refine(db, cluster_id=0, run_id=REFINE_RUN, min_sub_size=5)
        assert result["split"] is True, result
        parts, labels = _split(db)
        assert asked and all(call for call in asked), asked
        assert any(PUBLIC_TEXT in s for call in asked for s in call), asked
        assert not any(PRIVATE_TEXT in s for call in asked for s in call), asked
        assert labels and not any(PRIVATE_TEXT in lbl for lbl in labels.values()), labels
        # A sub-cluster of private members only is never sent to the labeller.
        only_private = [c for c, m in parts.items() if m <= set(private)]
        assert only_private, parts
        for c in only_private:
            assert labels[c] == f"cluster-{c}", labels
    finally:
        _cleanup(db, ids, group)


def test_interactive_refinement_shows_public_members_only(db, seed_agent, monkeypatch, capsys):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        public, private = _refine_members(cur, seed_agent, group, text=PRIVATE_TEXT,
                                          visibility="group")
    db.commit()
    ids = public + private
    answers = ["x,y"]
    monkeypatch.setattr("builtins.input", lambda _p="": answers.pop(0) if answers else "0")
    try:
        _place_in_cluster_0(db, ids)
        labeled, _, names = R.interactive_label(db, 0, REFINE_RUN)
        shown = capsys.readouterr().err
        assert PRIVATE_TEXT not in shown
        assert PUBLIC_TEXT in shown
        assert names == ["x", "y"]
        assert labeled and set(labeled) <= set(public), labeled
    finally:
        _cleanup(db, ids, group)
