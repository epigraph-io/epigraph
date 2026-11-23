"""--relabel-all reaches themes with no 1536-d centroid (backlog 7d4a3b67).

The --relabel-all repair replaces labels stored before the public-only rule
(theme_lib.public_label_source). It used to read only `centroid IS NOT NULL`
themes and sample only members with a 1536-d embedding, so a theme whose
centroid is 3072-d only (seed_themes_from_textbooks, for a section embedded
only at 3072-d) or absent kept whatever label it had, private text included.
"""
import uuid

from tests.theme.conftest import make_embedding
from tests.theme.test_label_excludes_intake import _group
from tests.theme.test_label_public_only import (
    LEAKED_DESCRIPTION,
    LEAKED_LABEL,
    _cleanup,
    _run_labeller,
    _stored,
)
from scripts import label_themes_llm as L

NEAR = "any-centroid public member nearest the 3072-d centroid"
FAR = "any-centroid public member far from the 3072-d centroid"
PRIVATE = "any-centroid group-private member ibis-onyx"


def _theme(cur, centroid_3072=None):
    """A theme with NO 1536-d centroid, optionally a 3072-d one."""
    cur.execute(
        "INSERT INTO claim_themes (label, description, claim_count, centroid, centroid_3072) "
        "VALUES (%s, %s, 2, NULL, %s::vector) RETURNING id",
        (LEAKED_LABEL, LEAKED_DESCRIPTION, centroid_3072),
    )
    return cur.fetchone()[0]


def _member(cur, agent_id, content, theme_id, seed_3072, owner=None, claim_id=None):
    """A current member with ONLY a 3072-d embedding (embedding is NULL)."""
    if owner is None:
        cur.execute(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, "
            "                    embedding_3072, theme_id) "
            "VALUES (COALESCE(%s::uuid, gen_random_uuid()), %s, sha256(%s::bytea), 0.5, %s, "
            "        %s::vector, %s) RETURNING id::text",
            (claim_id, content, content, agent_id, make_embedding(seed_3072, dim=3072),
             theme_id),
        )
    else:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, "
            "                    embedding_3072, theme_id, visibility, owner_group_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s, 'group', %s) "
            "RETURNING id::text",
            (content, content, agent_id, make_embedding(seed_3072, dim=3072), theme_id, owner),
        )
    return cur.fetchone()[0]


def test_relabel_all_reaches_themes_without_a_1536d_centroid(db, seed_agent, monkeypatch):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        only_3072 = _theme(cur, centroid_3072=make_embedding(7, dim=3072))
        no_centroid = _theme(cur)
        # FAR gets the smaller id, so the id tie-break alone would put it
        # first: only the 3072-d distance ordering puts NEAR first.
        far_id, near_id = sorted(str(uuid.uuid4()) for _ in range(2))
        ids = [
            _member(cur, seed_agent, FAR, only_3072, seed_3072=40, claim_id=far_id),
            _member(cur, seed_agent, NEAR, only_3072, seed_3072=7, claim_id=near_id),
            _member(cur, seed_agent, PRIVATE, only_3072, seed_3072=7, owner=group),
            _member(cur, seed_agent, f"{PRIVATE} 2", no_centroid, seed_3072=7, owner=group),
        ]
    db.commit()
    try:
        prompts = _run_labeller(monkeypatch, "--relabel-all")
        db.rollback()

        # The 3072-d-only theme is labelled from its public members, nearest
        # its 3072-d centroid first; the private member never reaches the LLM.
        assert len(prompts) == 1, prompts
        assert NEAR in prompts[0] and FAR in prompts[0]
        assert prompts[0].index(NEAR) < prompts[0].index(FAR)
        assert "ibis-onyx" not in prompts[0]
        assert _stored(db, only_3072) == ("LLM label", "LLM description")

        # No centroid at all and no public member: the leaked label is
        # replaced by the placeholder.
        assert _stored(db, no_centroid) == (L.NO_PUBLIC_MEMBER_LABEL, "")
    finally:
        _cleanup(db, ids, group)


def test_a_superseded_member_is_not_sampled(db, seed_agent, monkeypatch):
    """Sampling no longer requires a 1536-d embedding, so it states the
    is_current filter that requirement implied (a deprecated claim has no
    embedding of either dimension: chk_deprecated_no_embedding)."""
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        theme = _theme(cur)
        old = _member(cur, seed_agent, "any-centroid superseded public member", theme, 7)
        cur.execute(
            "UPDATE claims SET is_current = false, embedding_3072 = NULL WHERE id = %s", (old,)
        )
    db.commit()
    try:
        assert _run_labeller(monkeypatch, "--relabel-all") == []
        db.rollback()
        assert _stored(db, theme) == (L.NO_PUBLIC_MEMBER_LABEL, "")
    finally:
        _cleanup(db, [old], group)
