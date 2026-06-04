#!/usr/bin/env python3
"""Shared helpers for the theme-clustering pipeline.

Centralises three things every clustering script needs and previously
duplicated: a memory-safe embedding loader, a statement_timeout guard (so a
killed client cannot orphan a multi-minute server-side UPDATE), and the
nearest-centroid boundary math.
"""
import json
import os
import uuid

import numpy as np
import psycopg2

DEFAULT_DATABASE_URL = "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph"


def connect(database_url=None):
    """Open a psycopg2 connection (admin role by default)."""
    url = database_url or os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)
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
