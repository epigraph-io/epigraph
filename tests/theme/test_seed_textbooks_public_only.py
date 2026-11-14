"""Textbook-seeded theme labels quote PUBLIC text only (backlog 157aae7b).

seed_themes_from_textbooks asks an LLM to name a theme from a textbook level-1
section and up to three level-3 atoms under it, and stores the answer as
`claim_themes.label` / `description`, which every viewer who can read one
member of the theme reads. So a group-private section or atom must reach
neither the LLM nor the stored label (theme_lib.public_label_source).

Fixtures are committed (the code under test commits) and removed afterwards.
"""
import json

from scripts import label_themes_llm as L
from scripts import seed_themes_from_textbooks as S
from tests.theme.conftest import make_embedding
from tests.theme.test_label_excludes_intake import _group

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
