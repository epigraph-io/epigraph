"""Textbook-seeded theme labels quote PUBLIC text only (backlog 157aae7b).

seed_themes_from_textbooks asks an LLM to name a theme from a textbook level-1
section and up to three level-3 atoms under it, and stores the answer as
`claim_themes.label` / `description`, which every viewer who can read one
member of the theme reads. So a group-private section or atom must reach
neither the LLM nor the stored label (theme_lib.public_label_source).

The seeding worker opens its own connection, so fixtures are committed and
removed afterwards. The LLM is replaced by a recorder.
"""
import argparse
import json
import uuid

from scripts import label_themes_llm as L
from scripts import seed_themes_from_textbooks as S
from tests.theme.conftest import TEST_DSN, make_embedding
from tests.theme.test_label_excludes_intake import _group

PUBLIC_SECTION = "seed-public-only public section on streamline flow"
PRIVATE_SECTION = "seed-public-only group-private section narwhal-garnet"
PUBLIC_ATOM = "seed-public-only public atom about pressure"
PRIVATE_ATOM = "seed-public-only group-private atom narwhal-garnet"


def _claim(cur, agent_id, content, level, group=None, visibility="public", seed=5):
    """A textbook claim at `level`: owned by `group` with `visibility` when
    `group` is given, else with the inherited tenancy columns (public on a
    fresh migrated database)."""
    props = json.dumps({"source_type": "Textbook", "level": str(level)})
    if group is None:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    properties) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s::jsonb) "
            "RETURNING id::text",
            (content, content, agent_id, make_embedding(seed), props),
        )
    else:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    properties, visibility, owner_group_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s::jsonb, %s, %s) "
            "RETURNING id::text",
            (content, content, agent_id, make_embedding(seed), props, visibility, group),
        )
    return cur.fetchone()[0]


def _decomposes(cur, parent, child):
    cur.execute(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) "
        "VALUES (%s, %s, 'claim', %s, 'claim', 'decomposes_to')",
        (str(uuid.uuid4()), parent, child),
    )


def _section(cur, agent_id, group, section_text, section_visibility, atoms):
    """A level-1 section with `atoms` [(text, visibility)] decomposed under it.
    Returns (section_id, every claim id)."""
    owner = group if section_visibility == "group" else None
    sid = _claim(cur, agent_id, section_text, 1, group=owner, visibility=section_visibility)
    ids = [sid]
    for text, vis in atoms:
        aid = _claim(cur, agent_id, text, 3, group=group if vis == "group" else None,
                     visibility=vis)
        _decomposes(cur, sid, aid)
        ids.append(aid)
    return sid, ids


def _cleanup(db, ids, group):
    db.rollback()
    with db.cursor() as cur:
        cur.execute(
            "DELETE FROM edges WHERE source_id::text = ANY(%s) OR target_id::text = ANY(%s)",
            (ids, ids),
        )
        cur.execute("UPDATE claims SET theme_id = NULL WHERE id::text = ANY(%s)", (ids,))
        cur.execute("DELETE FROM claim_themes")
        cur.execute("DELETE FROM claims WHERE id::text = ANY(%s)", (ids,))
        cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
        cur.execute("DELETE FROM groups WHERE id = %s", (group,))
    db.commit()


def _seed_all(db, monkeypatch, dry_run=False):
    """Run the seeding worker over every unseeded section, with the LLM replaced
    by a recorder. Returns (worker results, [(section, atoms) sent to the LLM])."""
    sent = []

    def fake_llm(section_content, atoms):
        sent.append((section_content, list(atoms)))
        return {"label": "LLM label", "description": "LLM description"}

    monkeypatch.setattr(S, "label_via_claude", fake_llm)
    args = argparse.Namespace(database_url=TEST_DSN, dry_run=dry_run)
    sections = S.fetch_textbook_l1_claims(db, None)
    db.rollback()
    return [S.seed_one(s, args) for s in sections], sent


def _stored(db, sid):
    with db.cursor() as cur:
        cur.execute(
            "SELECT id, label, description FROM claim_themes "
            "WHERE properties->>'source_textbook_claim_id' = %s",
            (sid,),
        )
        row = cur.fetchone()
    db.rollback()
    return row


def test_a_private_section_is_seeded_with_the_placeholder_and_no_llm_call(
    db, seed_agent, monkeypatch
):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        sid, ids = _section(cur, seed_agent, group, PRIVATE_SECTION, "group",
                            [(PUBLIC_ATOM, "public"), (PRIVATE_ATOM, "group")])
    db.commit()
    try:
        # --dry-run sends nothing to the LLM either, and writes nothing.
        results, sent = _seed_all(db, monkeypatch, dry_run=True)
        assert sent == []
        assert [r["status"] for r in results] == ["dry"], results
        assert _stored(db, sid) is None

        results, sent = _seed_all(db, monkeypatch)
        assert sent == []
        assert [r["status"] for r in results] == ["ok"], results
        theme_id, label, description = _stored(db, sid)
        assert label == L.NO_PUBLIC_MEMBER_LABEL
        assert description == ""
        assert L.is_placeholder_label(label)  # label_themes_llm names it later
        # The theme still anchors the section: every member is assigned to it.
        with db.cursor() as cur:
            cur.execute("SELECT count(*) FROM claims WHERE theme_id = %s", (theme_id,))
            assert cur.fetchone()[0] == len(ids)
        db.rollback()
    finally:
        _cleanup(db, ids, group)


def test_a_public_section_is_labelled_from_public_atoms_only(db, seed_agent, monkeypatch):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        sid, ids = _section(cur, seed_agent, group, PUBLIC_SECTION, "public",
                            [(PUBLIC_ATOM, "public"), (PRIVATE_ATOM, "group")])
    db.commit()
    try:
        results, sent = _seed_all(db, monkeypatch)
        assert [r["status"] for r in results] == ["ok"], results
        assert sent == [(PUBLIC_SECTION, [PUBLIC_ATOM])], sent
        _, label, description = _stored(db, sid)
        assert (label, description) == ("LLM label", "LLM description")
    finally:
        _cleanup(db, ids, group)


def test_the_placeholder_survives_drop_auto_themes(db, seed_agent):
    """--drop-auto-after deletes every `auto-%` theme and unassigns its members.
    A theme no public member could name must not be swept up with them: losing
    a seeded one's row would let the next seed run label its section again."""
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        cur.execute(
            "INSERT INTO claim_themes (label, description, claim_count) "
            "VALUES (%s, '', 1) RETURNING id",
            (L.NO_PUBLIC_MEMBER_LABEL,),
        )
        placeholder = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO claim_themes (label, description, claim_count) "
            "VALUES ('auto-7', '', 1) RETURNING id"
        )
        auto = cur.fetchone()[0]
        kept = _claim(cur, seed_agent, PRIVATE_ATOM, 3, group=group, visibility="group")
        freed = _claim(cur, seed_agent, PUBLIC_ATOM, 3)
        cur.execute("UPDATE claims SET theme_id = %s WHERE id = %s", (placeholder, kept))
        cur.execute("UPDATE claims SET theme_id = %s WHERE id = %s", (auto, freed))
    db.commit()
    try:
        assert S.drop_auto_themes(db) == 1
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT id FROM claim_themes")
            assert [r[0] for r in cur.fetchall()] == [placeholder]
            cur.execute(
                "SELECT id::text, theme_id FROM claims WHERE id::text = ANY(%s)",
                ([kept, freed],),
            )
            assert dict(cur.fetchall()) == {kept: placeholder, freed: None}
        db.rollback()
    finally:
        _cleanup(db, [kept, freed], group)
