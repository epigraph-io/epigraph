#!/usr/bin/env python3
"""Shared helpers for the theme-clustering pipeline.

Centralises three things every clustering script needs and previously
duplicated: a memory-safe embedding loader, a statement_timeout guard (so a
killed client cannot orphan a multi-minute server-side UPDATE), and the
nearest-centroid boundary math.
"""
import json
import uuid

import numpy as np
import psycopg2

from maintenance_dsn import maintenance_dsn as _maintenance_dsn

DEFAULT_DATABASE_URL = "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph"

# The label stored for a theme no public member can name (`public_label_source`):
# there is no text every viewer may read. label_themes_llm.is_placeholder_label
# matches it, so a later labelling run names the theme once a public member
# joins. Its prefix is deliberately NOT `auto-`: seed_themes_from_textbooks
# --drop-auto-after deletes every `auto-%` theme and unassigns its members,
# which would discard this theme (and, for a seeded one, its
# source_textbook_claim_id, so the next seed run would label the section again).
NO_PUBLIC_MEMBER_LABEL = "unnamed-no-public-member"


def maintenance_dsn(default=DEFAULT_DATABASE_URL):
    """Resolve the DSN a corpus-wide script should connect on.

    A thin binding of `maintenance_dsn.maintenance_dsn` to this family's
    default. The RULE — `MAINTENANCE_DATABASE_URL` wins, then `DATABASE_URL`,
    then `default`, and a refusal when the two name different databases — lives
    in `scripts/maintenance_dsn.py` and is stated once there, because nineteen
    scripts share it and nineteen copies of a guard is nineteen places for it to
    drift. Read that module for why the precedence needs a guard at all and why
    privilege is deliberately not asserted in Python.

    Why the theme pipeline in particular needs it: it enumerates, re-clusters
    and UPDATEs the whole claim corpus, so once RLS is active (PR-17) an
    ordinary application connection makes every one of those statements match a
    subset — the SELECTs see less, the UPDATEs touch nothing, and the script
    exits 0.

    NOTE — pre-existing and NOT changed here: `DEFAULT_DATABASE_URL` hardcodes
    a production role and database. That is a long-standing property of this
    script family, not something PR-15 introduced, and changing it would alter
    where a dozen operator scripts point by default. Flagged, not fixed.
    """
    return _maintenance_dsn(default)


def not_intake_owned(alias="c"):
    """SQL predicate: claim `alias` is NOT owned by the bug-report intake group.

    Migration 207's intake files private bug reports, written by agents that
    are not members of the group that triages them, as claims owned by the
    group `bug_report_intake_settings` names. It is keyed on the CURRENTLY
    configured intake group: a report triage moves out of that group (or every
    report, once the operator names another group) is no longer matched. With
    no settings row it matches nothing.

    Not used on its own by any label path: `public_label_source` conjoins it
    with the public-visibility test, so a report the intake group made public
    is still never quoted in a stored label.
    """
    return (
        "NOT EXISTS (SELECT 1 FROM bug_report_intake_settings bri "
        f"WHERE bri.intake_group_id = {alias}.owner_group_id)"
    )


def public_label_source(alias="c"):
    """SQL predicate: claim `alias`'s text may be quoted in a STORED label.

    A stored label (`cluster_labels.label`, which project_to_themes copies onto
    a theme, and `claim_themes.label` / `description` from label_themes_llm and
    seed_themes_from_textbooks) is
    not viewer-derived: it is shown to every viewer who can read one member of
    the theme. So only text EVERY viewer may read can go into one, which is a
    `visibility = 'public'` claim. A group-private member's text, summarised
    or excerpted, would publish wording only its owner group may read. An
    intake-owned claim (`not_intake_owned`) is excluded even when public.

    Every path that turns member CONTENT into a stored label applies it, to
    the label samples only (membership, sizes and centroids are unchanged):
      * label_themes_llm.load_themes_with_samples (claim_themes.label and
        description, LLM); a theme with no public member gets the placeholder
        NO_PUBLIC_MEMBER_LABEL and no LLM call;
      * seed_themes_from_textbooks (claim_themes.label and description, LLM
        over a textbook level-1 section and sampled level-3 atoms): the
        section is sent only when it passes this predicate, else the theme is
        seeded with NO_PUBLIC_MEMBER_LABEL and no LLM call; the atoms are
        filtered by it;
      * cluster_claims.label_clusters and evidential_clustering.store_results
        (cluster_labels, member-text excerpts);
      * refine_clusters.auto_refine (cluster_labels, LLM), the split step of
        theme_pipeline's grow loop: a sub-cluster with no public member keeps
        its `cluster-<id>` placeholder;
      * refine_clusters.interactive_label (cluster_labels via
        train_and_apply): the operator who types the sub-label names is shown
        only public members' text.
    Checked and NOT routed through it, each for its stated reason:
      * anchor_papers_to_themes writes no theme row: its LLM-derived
        `refined_anchor_label` is stored as an edge property through the API,
        so it is outside theme labels (a separate question);
      * project_to_themes copies cluster_labels (filtered above);
        split_theme, maintain_themes.auto_split_theme and the
        create-with-centroid route write placeholder or derived labels;
      * split_theme --dry-run and subcluster_outliers are read-only reports
        that print member text to the maintenance operator running them and
        store nothing. A theme an operator later creates from what they read
        (create-with-centroid) carries a label that operator writes through a
        separate route, as after any maintenance read; interactive_label is
        filtered because it is itself the tool that stores what the operator
        types;
      * the API's experiment `centroid_summary` is computed per request from
        a viewer-scoped neighborhood, so it shows only claims the caller can
        already read.
    Labels stored before this rule existed are not rewritten by it: re-run
    label_themes_llm with --relabel-all (and re-label cluster runs) to replace
    them. That run reads only themes with a 1536-d `centroid`; a seeded theme
    whose section had only 3072-d embeddings has none and needs a separate
    relabel.
    """
    return f"({alias}.visibility = 'public' AND {not_intake_owned(alias)})"


def connect(database_url=None):
    """Open a psycopg2 connection (admin role by default)."""
    url = database_url or maintenance_dsn()
    return psycopg2.connect(url)


def set_statement_timeout(conn, ms=600000):
    """Bound every statement on this connection so a killed client cannot leave
    an orphaned long-running UPDATE holding row locks (observed: a 23-min
    orphaned `UPDATE claims SET theme_id=NULL` that lock-blocked the retry)."""
    with conn.cursor() as cur:
        cur.execute("SET statement_timeout = %s", (ms,))
    conn.commit()


def new_run_id():
    """Fresh consolidated cluster_run_id (one per grow-cycle)."""
    return str(uuid.uuid4())


def parse_embeddings(text_rows):
    """Parse a list of pgvector `embedding::text` strings into a float32 matrix.

    Builds the array row-by-row into a preallocated buffer to avoid the
    transient ~24 B/float Python-list blow-up that OOMs at large batch sizes.
    """
    n = len(text_rows)
    if n == 0:
        return np.empty((0,), dtype=np.float32)
    first = json.loads(text_rows[0])
    out = np.empty((n, len(first)), dtype=np.float32)
    out[0] = first
    for i in range(1, n):
        out[i] = json.loads(text_rows[i])
    return out


def load_embeddings_for_ids(conn, ids, dim=1536, chunk=5000):
    """Load embeddings for a list of claim ids into an (n, dim) float32 array,
    preserving the order of `ids`. Fetches in id-chunks so only `chunk` rows of
    embedding text are resident at once — avoids the multi-GB transient that
    fetching+parsing tens of thousands of embeddings at once produces.
    """
    out = np.empty((len(ids), dim), dtype=np.float32)
    pos = {cid: i for i, cid in enumerate(ids)}
    for start in range(0, len(ids), chunk):
        sub = ids[start:start + chunk]
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id::text, embedding::text FROM claims "
                "WHERE id = ANY(%s::uuid[]) AND embedding IS NOT NULL",
                (sub,),
            )
            for cid, etext in cur.fetchall():
                out[pos[cid]] = json.loads(etext)
    return out


def iter_claim_embeddings(conn, batch_size=50000, where="c.embedding IS NOT NULL AND c.is_current = true"):
    """Yield (claim_ids, embeddings) chunks over claims matching `where`,
    ordered by id (stable OFFSET paging). Memory-safe: one batch resident."""
    offset = 0
    while True:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT c.id::text, c.embedding::text FROM claims c "
                f"WHERE {where} ORDER BY c.id LIMIT %s OFFSET %s",
                (batch_size, offset),
            )
            rows = cur.fetchall()
        if not rows:
            break
        ids = [r[0] for r in rows]
        embs = parse_embeddings([r[1] for r in rows])
        yield ids, embs
        offset += len(rows)


def boundary_metrics(dists):
    """Given a 1-D array of distances to all centroids, return
    (nearest_idx, nearest_dist, second_dist, boundary_ratio, silhouette).
    boundary_ratio = nearest/second (0 when second==0); silhouette = 1-boundary."""
    order = np.argsort(dists)
    nearest = int(order[0])
    nearest_dist = float(dists[nearest])
    second_dist = float(dists[order[1]]) if len(dists) > 1 else 0.0
    boundary = nearest_dist / second_dist if second_dist > 0 else 0.0
    return nearest, nearest_dist, second_dist, boundary, 1.0 - boundary
