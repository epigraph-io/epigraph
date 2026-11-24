"""INSTANTIATES edge anchor labels are built from PUBLIC text only (backlog 7d4a3b67).

anchor_papers_to_themes stores the judge's `refined_anchor_label` (or, when the
judge gives none, the candidate's label, which for a review-paper L2 candidate
is that paragraph's raw content) as the `anchor_label` property of an
INSTANTIATES edge. A stored label is not viewer-derived, so text from a
group-private paper claim or review paragraph must not reach it
(theme_lib.public_label_source); such an edge gets
NO_PUBLIC_SOURCE_ANCHOR_LABEL instead. Membership (theme_id, which edges
exist) is outside the rule and unchanged.

Runs the real candidate queries against the test DB; the judge and the API
client are replaced by recorders.
"""
import json
import uuid

from scripts import anchor_papers_to_themes as A
from tests.theme.conftest import make_embedding
from tests.theme.test_label_excludes_intake import _group

SEED = 5
PUB_PAPER = "anchor-public paper atom on adatom diffusion"
PRIV_PAPER = "anchor-private paper atom kestrel-jade"
PUB_REVIEW = "anchor-public review paragraph on surface kinetics"
PRIV_REVIEW = "anchor-private review paragraph osprey-topaz"
TEXTBOOK = "anchor textbook section on diffusion"
THEME_LABEL = "Surface diffusion"


def _claim(cur, agent_id, content, props, group=None):
    if group is None:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    properties) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s::jsonb) RETURNING id::text",
            (content, content, agent_id, make_embedding(SEED), json.dumps(props)),
        )
    else:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    properties, visibility, owner_group_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s::jsonb, 'group', %s) "
            "RETURNING id::text",
            (content, content, agent_id, make_embedding(SEED), json.dumps(props), group),
        )
    return cur.fetchone()[0]


def _decomposes(cur, parent, child):
    cur.execute(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) "
        "VALUES (%s, %s, 'claim', %s, 'claim', 'decomposes_to')",
        (str(uuid.uuid4()), parent, child),
    )


class FakeApi:
    """Records INSTANTIATES edge POSTs; accepts the anchored_at PATCH."""

    class _Ok:
        status_code = 201

        def raise_for_status(self):
            pass

    def __init__(self):
        self.edges = {}

    def post(self, path, json):
        assert path == "/api/v1/edges"
        key = (str(json["source_id"]), str(json["target_id"]))
        self.edges[key] = json["properties"]["anchor_label"]
        return self._Ok()

    def patch(self, path, json):
        return self._Ok()


def fake_judge(paper_text, label, description):
    """A judge that says yes and, like the model, builds its refined label
    from the texts it was shown, except for the private review paragraph,
    where it gives none (so the caller's fallback, the candidate's own label,
    applies)."""
    verdict = {"verdict": "yes", "confidence": 0.9}
    if not label.startswith("anchor-private review"):
        verdict["refined_anchor_label"] = f"{paper_text} ~ {label}"
    return verdict


def test_anchor_labels_quote_public_text_only(db, seed_agent, monkeypatch):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        frontier = _claim(cur, seed_agent, "anchor frontier paper",
                          {"source_type": "Paper", "level": "0", "document_type": "frontier"})
        review = _claim(cur, seed_agent, "anchor review paper",
                        {"source_type": "Paper", "level": "0", "document_type": "review"})
        atom = {"source_type": "Paper", "level": "3"}
        pub_paper = _claim(cur, seed_agent, PUB_PAPER, atom)
        priv_paper = _claim(cur, seed_agent, PRIV_PAPER, atom, group=group)
        para = {"source_type": "Paper", "level": "2"}
        pub_review = _claim(cur, seed_agent, PUB_REVIEW, para)
        priv_review = _claim(cur, seed_agent, PRIV_REVIEW, para, group=group)
        textbook = _claim(cur, seed_agent, TEXTBOOK, {"source_type": "Textbook", "level": "1"})
        for parent, child in [(frontier, pub_paper), (frontier, priv_paper),
                              (review, pub_review), (review, priv_review)]:
            _decomposes(cur, parent, child)
        cur.execute(
            "INSERT INTO claim_themes (label, description, claim_count, centroid, properties) "
            "VALUES (%s, '', 1, %s::vector, %s::jsonb)",
            (THEME_LABEL, make_embedding(SEED), json.dumps({"source_textbook_claim_id": textbook})),
        )
        ids = [frontier, review, pub_paper, priv_paper, pub_review, priv_review, textbook]
    db.commit()
    monkeypatch.setattr(A, "judge_via_claude", fake_judge)
    api = FakeApi()
    try:
        claims = {str(c["id"]): c for c in A.fetch_paper_claims(db, "both", 3, None)}
        db.rollback()
        assert claims[pub_paper]["public_source"] is True
        assert claims[priv_paper]["public_source"] is False
        for paper in (pub_paper, priv_paper):
            A.anchor_one(db, api, claims[paper], "both", top_k=50, min_sim=0.45,
                         maybe_threshold=0.6, dry_run=False)
        db.rollback()

        placeholder = A.NO_PUBLIC_SOURCE_ANCHOR_LABEL
        # A public paper atom and public targets: the judge's label is kept.
        assert api.edges[(pub_paper, textbook)] == f"{PUB_PAPER} ~ {THEME_LABEL}"
        assert api.edges[(pub_paper, pub_review)] == f"{PUB_PAPER} ~ {PUB_REVIEW}"
        # A private review paragraph: no label from it, refined or raw.
        assert api.edges[(pub_paper, priv_review)] == placeholder
        # A private paper atom: every edge from it gets the placeholder.
        assert api.edges[(priv_paper, textbook)] == placeholder
        assert api.edges[(priv_paper, pub_review)] == placeholder
        assert api.edges[(priv_paper, priv_review)] == placeholder
        stored = " ".join(api.edges.values())
        assert "kestrel-jade" not in stored and "osprey-topaz" not in stored, api.edges
        # Membership is outside the rule: both atoms still take the theme.
        with db.cursor() as cur:
            cur.execute("SELECT count(*) FROM claims WHERE id::text = ANY(%s) "
                        "AND theme_id IS NOT NULL", ([pub_paper, priv_paper],))
            assert cur.fetchone()[0] == 2
        db.rollback()
    finally:
        db.rollback()
        with db.cursor() as cur:
            cur.execute("DELETE FROM edges WHERE source_id::text = ANY(%s) "
                        "OR target_id::text = ANY(%s)", (ids, ids))
            cur.execute("UPDATE claims SET theme_id = NULL WHERE id::text = ANY(%s)", (ids,))
            cur.execute("DELETE FROM claim_themes")
            cur.execute("DELETE FROM claims WHERE id::text = ANY(%s)", (ids,))
            cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
            cur.execute("DELETE FROM groups WHERE id = %s", (group,))
        db.commit()


def test_a_label_without_the_public_flag_fails_closed():
    """A claim or candidate dict that does not carry `public_source` (built
    by some other caller) is treated as not public."""
    verdict = {"verdict": "yes", "refined_anchor_label": "derived"}
    assert A.stored_anchor_label({}, {"label": "x", "public_source": True}, verdict) \
        == A.NO_PUBLIC_SOURCE_ANCHOR_LABEL
    assert A.stored_anchor_label({"public_source": True}, {"label": "x"}, verdict) \
        == A.NO_PUBLIC_SOURCE_ANCHOR_LABEL
    assert A.stored_anchor_label({"public_source": True},
                                 {"label": "x", "public_source": True}, verdict) == "derived"
    assert A.stored_anchor_label({"public_source": True},
                                 {"label": "x", "public_source": True}, {"verdict": "yes"}) == "x"
