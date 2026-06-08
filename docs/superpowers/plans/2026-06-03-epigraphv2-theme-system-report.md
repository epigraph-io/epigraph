# EpigraphV2 Theme-System Re-port — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect and complete the already-ported V2 clustering scripts so the full engine functions end-to-end — grow ~60–72 coherent clusters in Model B, project them into the active `claim_themes`/`claims.theme_id` model, and label them — fixing the broken middle where nothing bridges clusters → themes.

**Architecture:** Python pipeline. `cluster_claims.py` (exists) seeds/assigns/discovers into Model B (`claim_clusters`/`cluster_centroids`/`cluster_labels`) with the full boundary signal. A new `refine_clusters.py --auto` splits high-variance clusters unattended. A new `project_to_themes.py` materialises Model A from the latest consolidated `cluster_run_id` (true 1536-d centroids). `label_themes_llm.py` (exists) names themes. A new `theme_pipeline.py` orchestrates a grow-loop + discrete steps. Shared `theme_lib.py` provides a memory-safe loader and `statement_timeout` guard.

**Tech Stack:** Python 3, psycopg2, numpy, umap-learn, scikit-learn, pytest 9; PostgreSQL + pgvector; the `claude` CLI (nested file-write pattern, haiku).

**Worktree:** `/home/jeremy/epigraph/.worktrees/theme-v2-report` on branch `feat/theme-v2-full-report` (off `origin/main` @ 169a85c). All paths below are relative to it. Run every command from this directory.

**Conventions that bind this plan:**
- Writes to clustering tables use the `epigraph_admin` role (no API endpoints exist for Model B), per repo CLAUDE.md. Default DSN `postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph`.
- Tests use `epigraph_db_repo_test` per CLAUDE.md (`postgres://epigraph:epigraph@localhost/epigraph_db_repo_test`).
- Memory: heavy runs execute under `systemd-run --user --scope -p MemoryMax=2500M` so the job, never postgres, is the OOM victim (the trial run OOM-thrashed at the 1.6 GB cap; 2.5 GB is safe with ~3 GB free).
- Commit messages follow the repo Epistemic Commit Protocol (type(scope): claim + Evidence/Reasoning/Verification). End with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File Map

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `migrations/051_formalize_cluster_labels.sql` | Formalize `cluster_labels` (prod drift) + perf indexes |
| Create | `scripts/theme_lib.py` | Shared: memory-safe embedding loader, `statement_timeout`, boundary math, run-id |
| Create | `scripts/project_to_themes.py` | Project latest cluster run → `claim_themes` + `claims.theme_id` (the missing link) |
| Create | `scripts/theme_pipeline.py` | Orchestrator: grow-loop + `grow`/`project`/`label`/`discover` subcommands + `--dry-run` |
| Modify | `scripts/refine_clusters.py` | Add `--auto` (embedding-subcluster + LLM label, non-interactive) |
| Modify | `scripts/label_themes_llm.py` | Pin `--model claude-haiku-4-5-20251001` |
| Modify | `scripts/cluster_claims.py` | Add `statement_timeout` guard + `--all-claims` seed flag |
| Create | `tests/theme/conftest.py` | pytest fixtures: test-DB connection + clean-slate + seed helpers |
| Create | `tests/theme/test_theme_lib.py` | Unit: parse/loader/boundary math |
| Create | `tests/theme/test_project_to_themes.py` | Unit + integration: cluster→theme projection |
| Create | `tests/theme/test_refine_auto.py` | Unit + integration: `--auto` prompt/parse + split write |
| Create | `tests/theme/test_label_model_pin.py` | Unit: claude arg list includes `--model haiku` |
| Create | `tests/theme/test_theme_pipeline.py` | Unit: grow-loop decision + stop-reason; `--dry-run` |

---

## Task 1: Migration — formalize `cluster_labels` + indexes

**Files:**
- Create: `migrations/051_formalize_cluster_labels.sql`

`cluster_labels` exists in prod but in no migration (a fresh DB or `sqlx migrate run` would diverge). `claim_clusters` already has `UNIQUE(claim_id)` (`claim_clusters_claim_id_key`) and `cluster_centroids` already has its `(cluster_run_id, cluster_id)` unique; this migration adds `cluster_labels` to match prod and the GROUP-BY index the discover/projection queries need.

- [ ] **Step 1: Write the migration**

Create `migrations/051_formalize_cluster_labels.sql`:

```sql
-- Formalize the cluster_labels table (present in prod, absent from migrations)
-- and add the cluster-run grouping index used by discover/projection queries.
-- IF NOT EXISTS makes this idempotent against DBs where it already drifted in.

CREATE TABLE IF NOT EXISTS cluster_labels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    cluster_run_id uuid NOT NULL,
    cluster_id integer NOT NULL,
    label text NOT NULL,
    sample_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT cluster_labels_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS cluster_labels_run_cluster_key
    ON cluster_labels (cluster_run_id, cluster_id);

CREATE INDEX IF NOT EXISTS claim_clusters_run_cluster_idx
    ON claim_clusters (cluster_run_id, cluster_id);
```

- [ ] **Step 2: Apply to the test DB and verify**

Run:
```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo sqlx migrate run --source migrations 2>&1 | tail -5
```
Expected: `051/migrate formalize_cluster_labels` applied (or "No migrations to run" if already current after a prior partial run — then confirm the table exists below).

Run:
```bash
PGPASSWORD=epigraph psql -h localhost -U epigraph -d epigraph_db_repo_test -c "\d cluster_labels" 2>&1 | head -12
```
Expected: table with `cluster_run_id`, `cluster_id`, `label`, `sample_count`, the unique index `cluster_labels_run_cluster_key`.

- [ ] **Step 3: Verify the migration is checksum-clean (no drift on prod)**

Run:
```bash
PGPASSWORD=epigraph psql -h localhost -U epigraph -d epigraph_db_repo_test -tAc \
  "SELECT version, description FROM _sqlx_migrations ORDER BY version DESC LIMIT 3;"
```
Expected: `51 | formalize_cluster_labels` is the latest row.

- [ ] **Step 4: Commit**

```bash
git add migrations/051_formalize_cluster_labels.sql
git commit -F - <<'EOF'
feat(db): formalize cluster_labels table + cluster-run index (migration 051)

**Evidence:**
- cluster_labels exists in prod (8 rows) but in no migration file; a fresh DB
  or `sqlx migrate run` would diverge, and the binary would panic on restart
  (VersionMissing) the moment any later migration lands.

**Reasoning:**
- CREATE TABLE IF NOT EXISTS matches the live schema exactly so applying it to
  prod is a no-op; adds the (cluster_run_id, cluster_id) unique the ON CONFLICT
  upserts rely on and the GROUP BY index discover/projection scan.

**Verification:**
- `cargo sqlx migrate run` against epigraph_db_repo_test applies clean; \d
  cluster_labels shows the unique index; _sqlx_migrations head = 51.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 2: `theme_lib.py` — shared helpers (TDD)

**Files:**
- Create: `scripts/theme_lib.py`
- Create: `tests/theme/test_theme_lib.py`
- Create: `tests/theme/conftest.py` (DB fixtures, shared by later tasks)

- [ ] **Step 1: Write the failing unit tests**

Create `tests/theme/test_theme_lib.py`:

```python
"""Unit tests for the shared theme-clustering helpers (pure functions only)."""
import numpy as np
import pytest

from scripts import theme_lib


def test_parse_embeddings_shape_and_dtype():
    rows = ["[0.0, 1.0, 2.0]", "[3.0, 4.0, 5.0]"]
    arr = theme_lib.parse_embeddings(rows)
    assert arr.dtype == np.float32
    assert arr.shape == (2, 3)
    assert arr[1, 2] == pytest.approx(5.0)


def test_parse_embeddings_empty():
    arr = theme_lib.parse_embeddings([])
    assert arr.shape == (0,)


def test_boundary_metrics_basic():
    # Distances to 3 centroids; nearest=index1 (0.2), second=0.5.
    dists = np.array([0.5, 0.2, 0.9], dtype=np.float32)
    nearest, nearest_dist, second_dist, boundary, sil = theme_lib.boundary_metrics(dists)
    assert nearest == 1
    assert nearest_dist == pytest.approx(0.2)
    assert second_dist == pytest.approx(0.5)
    assert boundary == pytest.approx(0.2 / 0.5)
    assert sil == pytest.approx(1.0 - 0.2 / 0.5)


def test_boundary_metrics_zero_second_is_safe():
    # Degenerate: only one centroid distance non-trivial; second is 0.0.
    dists = np.array([0.0, 0.0], dtype=np.float32)
    nearest, nearest_dist, second_dist, boundary, sil = theme_lib.boundary_metrics(dists)
    assert boundary == 0.0  # guarded division
    assert sil == 1.0
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/theme/test_theme_lib.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'scripts.theme_lib'` (or `scripts` not a package). Fixed in Step 3 + Step 5.

- [ ] **Step 3: Implement `theme_lib.py`**

Create `scripts/theme_lib.py`:

```python
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
```

- [ ] **Step 4: Make `scripts/` and `tests/theme/` importable + add conftest**

Create empty `scripts/__init__.py`:
```bash
touch scripts/__init__.py
```

Create `tests/theme/conftest.py`:

```python
"""Shared pytest fixtures for theme-pipeline integration tests.

Uses epigraph_db_repo_test (per repo CLAUDE.md). Skips the whole module if the
DB or required tables are missing, so unit tests still run on a bare checkout.
"""
import os
import uuid

import psycopg2
import pytest

TEST_DSN = os.environ.get(
    "THEME_TEST_DATABASE_URL",
    "postgres://epigraph:epigraph@localhost/epigraph_db_repo_test",
)
REQUIRED = ["claims", "claim_themes", "claim_clusters", "cluster_centroids", "cluster_labels"]


@pytest.fixture
def db():
    try:
        conn = psycopg2.connect(TEST_DSN)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"test DB unavailable ({TEST_DSN}): {e}")
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name = ANY(%s)",
            (REQUIRED,),
        )
        if cur.fetchone()[0] < len(REQUIRED):
            conn.close()
            pytest.skip("required tables missing — run `cargo sqlx migrate run` on the test DB")
    # Clean slate for the clustering tables.
    with conn.cursor() as cur:
        cur.execute("UPDATE claims SET theme_id = NULL WHERE theme_id IS NOT NULL")
        cur.execute("DELETE FROM claim_clusters")
        cur.execute("DELETE FROM cluster_centroids")
        cur.execute("DELETE FROM cluster_labels")
        cur.execute("DELETE FROM claim_themes")
    conn.commit()
    yield conn
    conn.rollback()
    conn.close()


def make_embedding(seed, dim=1536):
    """Deterministic unit-ish 1536-d vector clustered around `seed`."""
    import numpy as np
    rng = np.random.RandomState(seed)
    v = rng.normal(0, 0.01, dim).astype("float32")
    v[seed % dim] += 1.0  # dominant axis = cluster identity
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


@pytest.fixture
def seed_agent(db):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO agents (public_key, display_name, agent_type) "
            "VALUES (sha256(gen_random_uuid()::text::bytea), 'theme-test', 'system') RETURNING id"
        )
        agent_id = cur.fetchone()[0]
    db.commit()
    return agent_id
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/theme/test_theme_lib.py -q`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add scripts/theme_lib.py scripts/__init__.py tests/theme/conftest.py tests/theme/test_theme_lib.py
git commit -F - <<'EOF'
feat(scripts): add theme_lib shared loader + statement_timeout + boundary math

**Evidence:**
- Each clustering script re-implemented embedding parsing inline; the default
  parse blew up to ~3.5 GB transient and OOM-thrashed. A killed client also
  orphaned a 23-min UPDATE during the trial run.

**Reasoning:**
- Centralise a preallocated-buffer parser, a chunked loader (one batch
  resident), a statement_timeout guard, and the nearest-centroid boundary
  math so every script shares one tested implementation.

**Verification:**
- pytest tests/theme/test_theme_lib.py: 4 passed (parse shape/dtype/empty,
  boundary math incl. zero-second guard).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 3: Harden `cluster_claims.py` (statement_timeout + `--all-claims`)

**Files:**
- Modify: `scripts/cluster_claims.py`

`cluster_claims.py` already writes the full Model-B signal. Two minimal changes: guard against orphaned writes, and allow seeding from all current claims (not only atomic leaves) per the spec's `--all-claims` lever.

- [ ] **Step 1: Add the `--all-claims` flag and timeout import**

In `scripts/cluster_claims.py`, add near the top after the existing imports:
```python
import theme_lib  # noqa: E402  (scripts/ is on sys.path when run as a script)
```
Add to `sample_atomic_claims` a sibling for all-claims sampling — insert this function directly below `sample_atomic_claims`:
```python
def sample_all_claims(conn, sample_size=5000):
    """Sample across ALL current+embedded claims (composites included)."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.id::text, c.embedding::text
            FROM claims c
            WHERE c.embedding IS NOT NULL AND c.is_current = true
            ORDER BY random() LIMIT %s
        """, (sample_size,))
        rows = cur.fetchall()
    ids = [r[0] for r in rows]
    embs = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
    return ids, embs
```

- [ ] **Step 2: Wire the flag into `seed_phase` and `main`**

In `seed_phase`, change the sampling line:
```python
    print(f"Phase 1: Sampling {sample_size} atomic claims...", file=sys.stderr)
    ids, embs = sample_atomic_claims(conn, sample_size)
```
to:
```python
    scope = "all" if all_claims else "atomic"
    print(f"Phase 1: Sampling {sample_size} {scope} claims...", file=sys.stderr)
    ids, embs = (sample_all_claims if all_claims else sample_atomic_claims)(conn, sample_size)
```
and change the `def seed_phase(conn, sample_size, k, run_id):` signature to:
```python
def seed_phase(conn, sample_size, k, run_id, all_claims=False):
```
In `main()`, add the argparse flag near the other flags:
```python
    parser.add_argument("--all-claims", action="store_true",
                        help="Seed from all current claims (default: atomic leaves only)")
```
and update the call:
```python
        reducer, centroids, k = seed_phase(conn, args.sample_size, args.k, run_id)
```
to:
```python
        reducer, centroids, k = seed_phase(conn, args.sample_size, args.k, run_id,
                                           all_claims=args.all_claims)
```

- [ ] **Step 3: Add the statement_timeout guard right after connecting**

In `main()`, immediately after `conn = psycopg2.connect(args.database_url)`:
```python
    theme_lib.set_statement_timeout(conn, ms=900000)  # 15 min ceiling per statement
```

- [ ] **Step 4: Smoke-test the CLI parses**

Run: `python3 scripts/cluster_claims.py --help 2>&1 | grep -E "all-claims|seed-only"`
Expected: both flags listed, no import error.

- [ ] **Step 5: Commit**

```bash
git add scripts/cluster_claims.py
git commit -F - <<'EOF'
feat(scripts): cluster_claims --all-claims seed scope + statement_timeout guard

**Evidence:**
- V2 seeds atomic leaves (sharper manifold); spec wants an --all-claims lever.
- A killed client orphaned a multi-minute UPDATE during the trial run.

**Reasoning:**
- Add sample_all_claims alongside the atomic sampler behind --all-claims; set a
  15-min statement_timeout via the shared theme_lib helper so server-side writes
  cannot outlive the client.

**Verification:**
- `cluster_claims.py --help` lists both flags and imports theme_lib cleanly.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 4: `project_to_themes.py` — the missing B → A link (TDD)

**Files:**
- Create: `scripts/project_to_themes.py`
- Create: `tests/theme/test_project_to_themes.py`

Materialise Model A from the latest consolidated run: one `claim_themes` row per cluster (label from `cluster_labels`, **true 1536-d centroid = mean of member embeddings** — not the padded 32-d UMAP centroid, since recall does pgvector search on `claim_themes.centroid`), set `claims.theme_id`, and record the `cluster_id ↔ theme_id` map in `claim_themes.properties`.

- [ ] **Step 1: Write the failing tests**

Create `tests/theme/test_project_to_themes.py`:

```python
"""Unit + integration tests for cluster → theme projection."""
import json
import pytest

from scripts import project_to_themes as P
from tests.theme.conftest import make_embedding


def test_theme_properties_records_lineage():
    props = P.theme_properties("run-123", 7)
    assert props["source"] == "cluster_run"
    assert props["cluster_run_id"] == "run-123"
    assert props["cluster_id"] == 7


def _seed_run(db, agent_id):
    """Two clusters, 3 claims each, with cluster_labels + claim_clusters."""
    run_id = "11111111-1111-1111-1111-111111111111"
    claim_ids = []
    with db.cursor() as cur:
        for cl in range(2):
            for i in range(3):
                content = f"c{cl}-{i}"
                cur.execute(
                    "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) "
                    "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector) RETURNING id::text",
                    (content, content, agent_id, make_embedding(cl)),
                )
                cid = cur.fetchone()[0]
                claim_ids.append(cid)
                cur.execute(
                    "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, "
                    "second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id, "
                    "centroid_distances) VALUES (%s,%s,0.1,0.5,0.2,0.8,%s,%s)",
                    (cid, cl, run_id, [0.1, 0.5]),
                )
            cur.execute(
                "INSERT INTO cluster_labels (cluster_run_id, cluster_id, label, sample_count) "
                "VALUES (%s,%s,%s,3)",
                (run_id, cl, f"cluster-{cl}"),
            )
    db.commit()
    return run_id, claim_ids


def test_project_run_materialises_themes(db, seed_agent):
    run_id, claim_ids = _seed_run(db, seed_agent)

    P.project_run(db, run_id)

    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM claim_themes")
        assert cur.fetchone()[0] == 2  # one theme per cluster
        cur.execute("SELECT count(*) FROM claims WHERE theme_id IS NULL AND id::text = ANY(%s)",
                    (claim_ids,))
        assert cur.fetchone()[0] == 0  # every seeded claim now themed
        cur.execute("SELECT count(*) FROM claim_themes WHERE centroid IS NULL")
        assert cur.fetchone()[0] == 0  # real 1536-d centroid set
        cur.execute("SELECT properties->>'cluster_run_id' FROM claim_themes LIMIT 1")
        assert cur.fetchone()[0] == run_id
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/theme/test_project_to_themes.py -q`
Expected: FAIL — `AttributeError: module 'scripts.project_to_themes' has no attribute 'theme_properties'`.

- [ ] **Step 3: Implement `project_to_themes.py`**

Create `scripts/project_to_themes.py`:

```python
#!/usr/bin/env python3
"""Project a Model-B cluster run into the active Model-A theme model.

For the chosen run (default: latest by cluster_centroids.created_at), wipe the
current claim_themes, then for each cluster create one claim_themes row whose
centroid is the TRUE 1536-d mean of its members' embeddings (recall does
pgvector search on this column), set claims.theme_id, and record the
cluster_id<->theme_id lineage in claim_themes.properties.
"""
import argparse
import json
import sys

import theme_lib


def theme_properties(run_id, cluster_id):
    """Lineage metadata stored on each projected theme."""
    return {"source": "cluster_run", "cluster_run_id": str(run_id), "cluster_id": int(cluster_id)}


def latest_run_id(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT cluster_run_id::text FROM cluster_centroids "
                    "ORDER BY created_at DESC LIMIT 1")
        row = cur.fetchone()
    if not row:
        print("ERROR: no cluster runs found in cluster_centroids", file=sys.stderr)
        sys.exit(1)
    return row[0]


def project_run(conn, run_id):
    """Replace claim_themes with one theme per cluster in `run_id`."""
    with conn.cursor() as cur:
        # Clean slate (targeted — only currently-themed claims are touched).
        cur.execute("UPDATE claims SET theme_id = NULL WHERE theme_id IS NOT NULL")
        cur.execute("DELETE FROM claim_themes")

        # Distinct clusters in this run, with their label.
        cur.execute("""
            SELECT cc.cluster_id, COALESCE(cl.label, 'auto-' || cc.cluster_id::text)
            FROM (SELECT DISTINCT cluster_id FROM claim_clusters WHERE cluster_run_id = %s) cc
            LEFT JOIN cluster_labels cl
              ON cl.cluster_run_id = %s AND cl.cluster_id = cc.cluster_id
            ORDER BY cc.cluster_id
        """, (run_id, run_id))
        clusters = cur.fetchall()

    created = 0
    for cluster_id, label in clusters:
        with conn.cursor() as cur:
            # Create the theme with the true 1536-d centroid = mean of members.
            cur.execute("""
                INSERT INTO claim_themes (label, description, claim_count, centroid, properties)
                SELECT %s, '', count(*),
                       avg(c.embedding)::vector(1536),
                       %s::jsonb
                FROM claims c
                JOIN claim_clusters cc ON cc.claim_id = c.id
                WHERE cc.cluster_run_id = %s AND cc.cluster_id = %s
                  AND c.embedding IS NOT NULL
                RETURNING id
            """, (label, json.dumps(theme_properties(run_id, cluster_id)), run_id, cluster_id))
            theme_id = cur.fetchone()[0]

            # Point member claims at the new theme.
            cur.execute("""
                UPDATE claims SET theme_id = %s, updated_at = NOW()
                WHERE id IN (SELECT claim_id FROM claim_clusters
                             WHERE cluster_run_id = %s AND cluster_id = %s)
            """, (theme_id, run_id, cluster_id))
        conn.commit()
        created += 1

    print(f"  Projected {created} themes from run {run_id}", file=sys.stderr)
    return created


def main():
    parser = argparse.ArgumentParser(description="Project a cluster run into claim_themes")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--run-id", default=None, help="Cluster run (default: latest)")
    args = parser.parse_args()

    conn = theme_lib.connect(args.database_url)
    theme_lib.set_statement_timeout(conn, ms=900000)
    run_id = args.run_id or latest_run_id(conn)
    created = project_run(conn, run_id)
    print(json.dumps({"status": "projected", "run_id": run_id, "themes": created}))
    conn.close()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/theme/test_project_to_themes.py -q`
Expected: 2 passed (skips if test DB unavailable — then run after starting it).

- [ ] **Step 5: Commit**

```bash
git add scripts/project_to_themes.py tests/theme/test_project_to_themes.py
git commit -F - <<'EOF'
feat(scripts): project cluster runs into claim_themes (the missing B->A link)

**Evidence:**
- cluster_claims.py fills Model B; maintain_themes/label_themes_llm presuppose
  Model A themes exist. Nothing bridged clusters -> themes, so the pipeline was
  broken in the middle and only 500/429K claims were themed.

**Reasoning:**
- Build one claim_themes row per cluster in the latest run; centroid is the true
  1536-d mean of members (recall searches this column) not the padded 32-d UMAP
  centroid; lineage recorded in properties for traceability and re-projection.

**Verification:**
- pytest tests/theme/test_project_to_themes.py: 2 passed — 2 clusters -> 2
  themes, zero unthemed members, non-null 1536-d centroids, lineage in props.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 5: `refine_clusters.py --auto` — unattended split (TDD)

**Files:**
- Modify: `scripts/refine_clusters.py`
- Create: `tests/theme/test_refine_auto.py`

Add a non-interactive mode that embedding-subclusters one cluster (UMAP+k-means, silhouette pick — the `subcluster_outliers.py` algorithm), LLM-labels each subcluster via the claude nested-file pattern, and writes the split into `claim_clusters` (`cluster_id*100+sub`) + `cluster_labels` under the **same run** (consolidated). The LLM call is isolated behind one function so tests monkeypatch it.

- [ ] **Step 1: Write the failing tests**

Create `tests/theme/test_refine_auto.py`:

```python
"""Unit + integration tests for refine_clusters.py --auto."""
import pytest

from scripts import refine_clusters as R
from tests.theme.conftest import make_embedding


def test_build_subcluster_prompt_contains_samples():
    prompt = R.build_subcluster_label_prompt(["alpha claim", "beta claim"])
    assert "alpha claim" in prompt and "beta claim" in prompt
    assert "theme name" in prompt.lower()


def test_parse_subcluster_label_strips_noise():
    assert R.parse_subcluster_label('"DNA Origami"') == "DNA Origami"
    assert R.parse_subcluster_label("Electrostatic Actuation.\nblah") == "Electrostatic Actuation"
    assert R.parse_subcluster_label("") == ""


def test_auto_refine_splits_cluster(db, seed_agent, monkeypatch):
    run_id = "22222222-2222-2222-2222-222222222222"
    # One cluster (id=0) holding two embedding blobs -> should split into 2.
    with db.cursor() as cur:
        for blob in range(2):
            for i in range(15):
                content = f"blob{blob}-{i}"
                cur.execute(
                    "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) "
                    "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector) RETURNING id::text",
                    (content, content, seed_agent, make_embedding(blob * 50)),
                )
                cid = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, "
                    "second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id, "
                    "centroid_distances) VALUES (%s,0,0.4,0.5,0.8,0.2,%s,%s)",
                    (cid, run_id, [0.4, 0.5]),
                )
    db.commit()

    # Avoid real claude: deterministic labels.
    monkeypatch.setattr(R, "llm_label_subcluster", lambda samples, idx: f"sub-{idx}")

    result = R.auto_refine(db, cluster_id=0, run_id=run_id, min_sub_size=5)
    assert result["split"] is True
    assert result["n_subclusters"] >= 2

    with db.cursor() as cur:
        cur.execute("SELECT count(DISTINCT cluster_id) FROM claim_clusters WHERE cluster_run_id=%s",
                    (run_id,))
        assert cur.fetchone()[0] >= 2  # cluster 0 replaced by 0*100+sub ids
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/theme/test_refine_auto.py -q`
Expected: FAIL — `AttributeError: ... has no attribute 'build_subcluster_label_prompt'`.

- [ ] **Step 3: Add the `--auto` implementation to `refine_clusters.py`**

In `scripts/refine_clusters.py`, add these imports near the top (after existing imports):
```python
import os
import subprocess
import time

import umap
from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import normalize
```

Add these functions above `def main()`:

```python
REFINE_RESULT_DIR = "/tmp/refine_labels"


def build_subcluster_label_prompt(samples):
    """Prompt asking the LLM for a concise theme name from sample claims."""
    body = "\n".join(f"- {s[:200]}" for s in samples[:10])
    return (
        "You are naming a sub-theme in a scientific knowledge graph.\n"
        "Representative claims:\n" + body +
        "\n\nReply with ONLY the theme name: 4-8 words, Title Case, no quotes, "
        "no punctuation, no explanation.\nTheme name:"
    )


def parse_subcluster_label(raw):
    """First non-empty line, stripped of quotes and trailing punctuation."""
    line = next((l.strip() for l in raw.splitlines() if l.strip()), "")
    return line.strip('"\'').rstrip(".,;:").strip()


def llm_label_subcluster(samples, idx):
    """Label one subcluster via the claude CLI (nested file-write pattern).
    Falls back to '' on any failure so a CLI outage cannot block a split."""
    os.makedirs(REFINE_RESULT_DIR, exist_ok=True)
    result_path = os.path.join(REFINE_RESULT_DIR, f"sub_{idx}.json")
    if os.path.exists(result_path):
        os.remove(result_path)
    prompt = build_subcluster_label_prompt(samples) + (
        f"\n\nWrite your answer as JSON {{\"label\": \"...\"}} to the file "
        f"{result_path} using the Write tool."
    )
    try:
        subprocess.run(
            ["claude", "-p", prompt, "--output-format", "json", "--max-turns", "1",
             "--model", "claude-haiku-4-5-20251001", "--dangerously-skip-permissions"],
            stdin=subprocess.DEVNULL, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=120, capture_output=True,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    for _ in range(10):
        if os.path.exists(result_path):
            import json as _json
            try:
                return parse_subcluster_label(_json.load(open(result_path)).get("label", ""))
            except Exception:  # noqa: BLE001
                return ""
        time.sleep(1)
    return ""


def auto_refine(conn, cluster_id, run_id, min_sub_size=50, min_silhouette=0.15):
    """Embedding-subcluster one cluster and write the split into the same run."""
    import json as _json
    import numpy as np

    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.id::text, c.content, c.embedding::text
            FROM claim_clusters cc JOIN claims c ON c.id = cc.claim_id
            WHERE cc.cluster_run_id = %s AND cc.cluster_id = %s AND c.embedding IS NOT NULL
        """, (run_id, cluster_id))
        rows = cur.fetchall()
    if len(rows) < 2 * min_sub_size:
        return {"split": False, "reason": "too few claims", "n_subclusters": 0}

    ids = [r[0] for r in rows]
    contents = [r[1] for r in rows]
    embs = np.array([_json.loads(r[2]) for r in rows], dtype=np.float32)

    reduced = umap.UMAP(n_components=16, metric="cosine", n_neighbors=15,
                        min_dist=0.0, random_state=42).fit_transform(embs)
    reduced = normalize(reduced.astype(np.float32), norm="l2")

    best_k, best_score, best_labels = 1, -1.0, None
    for k in range(2, min(8, len(rows) // min_sub_size) + 1):
        km = MiniBatchKMeans(n_clusters=k, n_init=5, random_state=42,
                             batch_size=min(512, len(reduced)))
        labels = km.fit_predict(reduced)
        score = silhouette_score(reduced, labels, sample_size=min(1000, len(reduced)))
        if score > best_score:
            best_k, best_score, best_labels = k, score, labels

    if best_k < 2 or best_score < min_silhouette:
        return {"split": False, "reason": f"no structure (sil={best_score:.3f})", "n_subclusters": 0}

    written = 0
    with conn.cursor() as cur:
        for sub in range(best_k):
            members = [ids[i] for i in range(len(ids)) if best_labels[i] == sub]
            if len(members) < min_sub_size:
                continue
            new_cid = cluster_id * 100 + sub
            samples = [contents[i] for i in range(len(ids)) if best_labels[i] == sub][:10]
            label = llm_label_subcluster(samples, sub) or f"cluster-{new_cid}"
            cur.execute("""
                UPDATE claim_clusters SET cluster_id = %s, computed_at = NOW()
                WHERE cluster_run_id = %s AND claim_id = ANY(%s::uuid[])
            """, (new_cid, run_id, members))
            cur.execute("""
                INSERT INTO cluster_labels (cluster_run_id, cluster_id, label, sample_count)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (cluster_run_id, cluster_id)
                DO UPDATE SET label = EXCLUDED.label, sample_count = EXCLUDED.sample_count
            """, (run_id, new_cid, label, len(members)))
            written += 1
    conn.commit()
    return {"split": True, "n_subclusters": written, "silhouette": float(best_score)}
```

Add to `main()`'s argparse (the `--cluster-id` is currently `required=True`; relax it for `--auto`):
```python
    parser.add_argument("--auto", action="store_true",
                        help="Non-interactive: embedding-subcluster + LLM label")
```
Change `parser.add_argument("--cluster-id", type=int, required=True)` to:
```python
    parser.add_argument("--cluster-id", type=int, required=False)
```
At the very top of `main()` after `conn = get_connection(...)` and run-id resolution, add an `--auto` branch that returns before the interactive path:
```python
    if args.auto:
        if args.cluster_id is None:
            print("ERROR: --auto requires --cluster-id", file=sys.stderr); sys.exit(1)
        import json as _json
        print(_json.dumps(auto_refine(conn, args.cluster_id, args.run_id)))
        conn.close(); return
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/theme/test_refine_auto.py -q`
Expected: 3 passed (integration test monkeypatches the LLM; skips if no test DB).

- [ ] **Step 5: Commit**

```bash
git add scripts/refine_clusters.py tests/theme/test_refine_auto.py
git commit -F - <<'EOF'
feat(scripts): add refine_clusters --auto (embedding-subcluster + LLM label)

**Evidence:**
- The grow-to-~72 mechanic ("isolated cluster within a previous k-means
  cluster") needed a human typing sub-labels in V2; the loop could not run
  unattended or in an orchestrator.

**Reasoning:**
- --auto UMAP+k-means subclusters one cluster, silhouette-gates the split, and
  LLM-labels each subcluster via the claude nested-file pattern (haiku), writing
  cluster_id*100+sub into the SAME run (consolidated). LLM call isolated behind
  llm_label_subcluster for testability + graceful fallback.

**Verification:**
- pytest tests/theme/test_refine_auto.py: 3 passed — prompt/parse units +
  integration splitting a 2-blob cluster into >=2 subclusters (LLM monkeypatched).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 6: Pin the labeler model in `label_themes_llm.py`

**Files:**
- Modify: `scripts/label_themes_llm.py`
- Create: `tests/theme/test_label_model_pin.py`

- [ ] **Step 1: Write the failing test**

Create `tests/theme/test_label_model_pin.py`:

```python
"""Unit test: the claude command line pins the haiku model."""
import inspect
from scripts import label_themes_llm as L


def test_claude_invocation_pins_haiku_model():
    src = inspect.getsource(L.call_claude_cli)
    assert "--model" in src
    assert "claude-haiku-4-5-20251001" in src
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/theme/test_label_model_pin.py -q`
Expected: FAIL — `--model` not present in `call_claude_cli`.

- [ ] **Step 3: Add the model flag**

In `scripts/label_themes_llm.py`, inside `call_claude_cli`, change the args list:
```python
                "claude", "-p", prompt,
                "--output-format", "json",
```
to:
```python
                "claude", "-p", prompt,
                "--output-format", "json",
                "--model", "claude-haiku-4-5-20251001",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/theme/test_label_model_pin.py -q`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/label_themes_llm.py tests/theme/test_label_model_pin.py
git commit -F - <<'EOF'
fix(scripts): pin label_themes_llm to claude-haiku-4-5-20251001

**Evidence:**
- call_claude_cli passed no --model, so theme labeling used the CLI default
  model — cost/latency unpredictable for a low-stakes bulk naming pass.

**Reasoning:**
- Naming from 10 nearest claims is low-stakes; haiku is the right tier and the
  spec calls for it explicitly.

**Verification:**
- pytest tests/theme/test_label_model_pin.py: 1 passed (source asserts the
  --model haiku flag is present).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 7: `theme_pipeline.py` — orchestrator (TDD)

**Files:**
- Create: `scripts/theme_pipeline.py`
- Create: `tests/theme/test_theme_pipeline.py`

Grow-loop over Model B then project + label. Pure decision functions are unit-tested; the heavy steps call the other scripts' functions.

- [ ] **Step 1: Write the failing unit tests**

Create `tests/theme/test_theme_pipeline.py`:

```python
"""Unit tests for the orchestrator's pure decision logic."""
from scripts import theme_pipeline as T


def test_select_clusters_to_split_picks_high_variance():
    stats = [
        {"cluster_id": 0, "size": 5000, "p95_dist": 0.9, "mean_boundary": 0.8},
        {"cluster_id": 1, "size": 300, "p95_dist": 0.9, "mean_boundary": 0.8},   # too small
        {"cluster_id": 2, "size": 5000, "p95_dist": 0.1, "mean_boundary": 0.1},  # coherent
    ]
    picked = T.select_clusters_to_split(stats, min_size=2000, p95_threshold=0.5,
                                        boundary_threshold=0.5)
    assert picked == [0]


def test_stop_reason_target_reached():
    assert T.stop_reason(current_k=72, target_k=72, iterations=3, max_iter=10,
                         n_selected=5) == "target_k reached"


def test_stop_reason_no_candidates():
    assert T.stop_reason(current_k=20, target_k=72, iterations=3, max_iter=10,
                         n_selected=0) == "no split candidates"


def test_stop_reason_max_iter():
    assert T.stop_reason(current_k=30, target_k=72, iterations=10, max_iter=10,
                         n_selected=5) == "max_iter reached"


def test_stop_reason_continue():
    assert T.stop_reason(current_k=30, target_k=72, iterations=2, max_iter=10,
                         n_selected=5) is None
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/theme/test_theme_pipeline.py -q`
Expected: FAIL — module/attribute missing.

- [ ] **Step 3: Implement `theme_pipeline.py`**

Create `scripts/theme_pipeline.py`:

```python
#!/usr/bin/env python3
"""Orchestrate the theme-clustering grow-loop + discrete steps.

Subcommands:
  grow      base -> (discover -> split high-variance clusters)* -> project -> label
  discover  report split candidates for the latest run (no writes)
  project   run project_to_themes for the latest/--run-id run
  label     run label_themes_llm

All grow writes happen in Model B under one consolidated run_id; project
materialises Model A; label names it. --dry-run reports the plan without writing.
"""
import argparse
import json
import subprocess
import sys

import theme_lib
import cluster_claims
import refine_clusters
import project_to_themes


def cluster_stats(conn, run_id):
    """Per-cluster size + p95 distance + mean boundary_ratio for the run."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT cluster_id, count(*),
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY centroid_distance),
                   avg(boundary_ratio)
            FROM claim_clusters WHERE cluster_run_id = %s GROUP BY cluster_id
        """, (run_id,))
        return [
            {"cluster_id": c, "size": n, "p95_dist": float(p or 0), "mean_boundary": float(b or 0)}
            for c, n, p, b in cur.fetchall()
        ]


def select_clusters_to_split(stats, min_size=2000, p95_threshold=0.5, boundary_threshold=0.5):
    """High-variance, large-enough clusters worth splitting."""
    return sorted(
        s["cluster_id"] for s in stats
        if s["size"] >= min_size
        and (s["p95_dist"] >= p95_threshold or s["mean_boundary"] >= boundary_threshold)
    )


def stop_reason(current_k, target_k, iterations, max_iter, n_selected):
    """Return a stop string, or None to continue."""
    if current_k >= target_k:
        return "target_k reached"
    if n_selected == 0:
        return "no split candidates"
    if iterations >= max_iter:
        return "max_iter reached"
    return None


def current_k(conn, run_id):
    with conn.cursor() as cur:
        cur.execute("SELECT count(DISTINCT cluster_id) FROM claim_clusters WHERE cluster_run_id=%s",
                    (run_id,))
        return cur.fetchone()[0]


def grow(conn, args):
    run_id = theme_lib.new_run_id()
    print(f"== base clustering (run {run_id}) ==", file=sys.stderr)
    reducer, centroids, k = cluster_claims.seed_phase(
        conn, args.sample_size, args.k, run_id, all_claims=args.all_claims)
    cluster_claims.assign_batch(conn, reducer, centroids, run_id, batch_size=args.batch_size)

    iterations = 0
    while True:
        stats = cluster_stats(conn, run_id)
        selected = select_clusters_to_split(stats, min_size=args.min_size)
        reason = stop_reason(current_k(conn, run_id), args.target_k, iterations,
                             args.max_iter, len(selected))
        print(f"  iter {iterations}: k={current_k(conn, run_id)} candidates={len(selected)} "
              f"stop={reason}", file=sys.stderr)
        if reason:
            print(f"  grow stopped: {reason}", file=sys.stderr)
            break
        if args.dry_run:
            print(f"  [dry-run] would split clusters {selected}", file=sys.stderr)
            break
        for cid in selected:
            refine_clusters.auto_refine(conn, cid, run_id, min_sub_size=args.min_size // 4)
        iterations += 1

    if args.dry_run:
        return {"status": "dry-run", "run_id": run_id, "k": current_k(conn, run_id)}

    project_to_themes.project_run(conn, run_id)
    subprocess.run([sys.executable, "scripts/label_themes_llm.py", "--relabel-all"], check=False)
    return {"status": "grown", "run_id": run_id, "k": current_k(conn, run_id)}


def main():
    p = argparse.ArgumentParser(description="Theme-clustering orchestrator")
    p.add_argument("command", choices=["grow", "discover", "project", "label"])
    p.add_argument("--database-url", default=None)
    p.add_argument("--sample-size", type=int, default=5000)
    p.add_argument("--batch-size", type=int, default=20000)
    p.add_argument("--k", type=int, default=None)
    p.add_argument("--all-claims", action="store_true")
    p.add_argument("--target-k", type=int, default=72)
    p.add_argument("--min-size", type=int, default=2000)
    p.add_argument("--max-iter", type=int, default=8)
    p.add_argument("--run-id", default=None)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    conn = theme_lib.connect(args.database_url)
    theme_lib.set_statement_timeout(conn, ms=900000)

    if args.command == "grow":
        print(json.dumps(grow(conn, args)))
    elif args.command == "discover":
        run_id = args.run_id or project_to_themes.latest_run_id(conn)
        print(json.dumps({"run_id": run_id,
                          "candidates": select_clusters_to_split(cluster_stats(conn, run_id),
                                                                 min_size=args.min_size)}))
    elif args.command == "project":
        run_id = args.run_id or project_to_themes.latest_run_id(conn)
        print(json.dumps({"status": "projected", "run_id": run_id,
                          "themes": project_to_themes.project_run(conn, run_id)}))
    elif args.command == "label":
        subprocess.run([sys.executable, "scripts/label_themes_llm.py", "--relabel-all"], check=False)
    conn.close()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run unit tests to verify they pass**

Run: `python3 -m pytest tests/theme/test_theme_pipeline.py -q`
Expected: 5 passed.

- [ ] **Step 5: Smoke-test the orchestrator imports + parses**

Run: `python3 scripts/theme_pipeline.py --help 2>&1 | grep -E "grow|discover|project|dry-run"`
Expected: subcommands + `--dry-run` listed, no import error.

- [ ] **Step 6: Commit**

```bash
git add scripts/theme_pipeline.py tests/theme/test_theme_pipeline.py
git commit -F - <<'EOF'
feat(scripts): add theme_pipeline orchestrator (grow-loop + discrete steps)

**Evidence:**
- The V2 grow-to-72 was a manual sequence of one-shot scripts; nothing drove
  base -> discover -> split -> project -> label or decided when to stop.

**Reasoning:**
- grow() runs base clustering then splits high-variance clusters in the same
  consolidated run until target_k / no-candidates / max_iter, then projects to
  Model A and labels. Decision logic (select_clusters_to_split, stop_reason) is
  pure + unit-tested; --dry-run reports the plan without writing.

**Verification:**
- pytest tests/theme/test_theme_pipeline.py: 5 passed; `theme_pipeline.py --help`
  lists all subcommands.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 8: End-to-end validation on the live DB (capped)

**Files:** none (operational verification).

- [ ] **Step 1: Confirm the migration is applied to prod**

Run:
```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph cargo sqlx migrate info --source migrations 2>&1 | tail -3
```
Expected: `051/formalize_cluster_labels ... installed` (apply with `migrate run` if pending — prod read is a no-op since the table already exists).

- [ ] **Step 2: Dry-run the grow plan (no writes)**

Run:
```bash
cd /home/jeremy/epigraph/.worktrees/theme-v2-report
systemd-run --user --scope -p MemoryMax=2500M --quiet bash -c \
 "DATABASE_URL=postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph \
  python3 -u scripts/theme_pipeline.py grow --dry-run --all-claims --batch-size 20000 \
  > /tmp/grow_dry.log 2>&1"
tail -20 /tmp/grow_dry.log
```
Expected: base clustering runs, prints `[dry-run] would split clusters [...]` and a projected k; no exceptions.

- [ ] **Step 3: Full grow run (capped, backgrounded, monitored)**

Run (background) and watch with a Monitor that covers progress AND failure signatures (`Traceback|Killed|OOM|Error|grow stopped|grown`):
```bash
systemd-run --user --scope -p MemoryMax=2500M --quiet bash -c \
 "DATABASE_URL=postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph \
  python3 -u scripts/theme_pipeline.py grow --all-claims --batch-size 20000 --target-k 72 \
  > /tmp/grow_full.log 2>&1"
```
Expected final log line: `{"status": "grown", "run_id": "...", "k": <40-72>}`.

- [ ] **Step 4: Verify coverage + model consistency**

Run:
```bash
PGPASSWORD=epigraph psql -h localhost -U epigraph -d epigraph -tA -c "
SELECT
  (SELECT count(*) FROM claim_themes) AS themes,
  (SELECT count(*) FROM claims WHERE theme_id IS NOT NULL) AS themed,
  (SELECT count(*) FROM claims WHERE theme_id IS NULL AND embedding IS NOT NULL AND is_current) AS unthemed,
  (SELECT count(DISTINCT cluster_id) FROM claim_clusters
     WHERE cluster_run_id=(SELECT cluster_run_id FROM cluster_centroids ORDER BY created_at DESC LIMIT 1)) AS clusters_latest_run,
  (SELECT count(*) FROM claim_clusters
     WHERE cluster_run_id=(SELECT cluster_run_id FROM cluster_centroids ORDER BY created_at DESC LIMIT 1)) AS claims_in_run;"
```
Expected: `themes` ≈ 40–72; `unthemed` = 0; `claims_in_run` ≈ 429K (matcher data refreshed); `clusters_latest_run` == `themes`.

- [ ] **Step 5: Verify recall still works (Model A consumers)**

Run:
```bash
PGPASSWORD=epigraph psql -h localhost -U epigraph -d epigraph -tA -c "
SELECT label, claim_count FROM claim_themes ORDER BY claim_count DESC LIMIT 10;"
```
Expected: human-readable labels (not `auto-NN`), sensible counts. Spot-check the MCP `recall` path returns themed results against `:3100` if convenient.

- [ ] **Step 6: Record the outcome**

Append a short results note (themes, coverage, run_id, wall-clock) to the spec file's end under a `## Run log` heading and commit:
```bash
git add docs/superpowers/specs/2026-06-03-epigraphv2-theme-system-report-design.md
git commit -m "docs(themes): record first full grow-run results (coverage, k, run_id)"
```

---

## Self-Review

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| `cluster_labels` migration (prod drift) | Task 1 |
| Shared memory-safe loader + statement_timeout | Task 2 (theme_lib) |
| Base seed/assign/discover writes Model B | Reuse `cluster_claims.py` + Task 3 hardening |
| Atomic-leaf default, `--all-claims` override | Task 3 |
| B → A projection (true 1536-d centroid, lineage) | Task 4 |
| Autonomous refine (`--auto`, LLM) + keep interactive | Task 5 (interactive path untouched) |
| Faithful read-only subcluster report | Reuse `subcluster_outliers.py` (unchanged) |
| LLM labeling pinned to haiku | Task 6 |
| Orchestrated grow-loop + discrete steps + dry-run + consolidated run | Task 7 |
| Steady-state reconciler | Reuse `maintain_themes.py` (unchanged; runs post-projection) |
| Fix stale 191K `claim_clusters` (matcher) | Task 8 step 4 (full run covers 429K) |
| Tests: boundary math, projection map, refine prompt/parse, integration | Tasks 2,4,5,6,7 |

**Placeholder scan:** none — every code step is complete; the only deferred value is the post-run results note (Task 8 step 6), which is data produced by the run, not a code placeholder.

**Type consistency:**
- `theme_lib.{connect,set_statement_timeout,new_run_id,parse_embeddings,boundary_metrics}` defined Task 2, used Tasks 3/4/7 ✓
- `project_to_themes.{theme_properties,project_run,latest_run_id}` defined Task 4, used Task 7 ✓
- `refine_clusters.{build_subcluster_label_prompt,parse_subcluster_label,llm_label_subcluster,auto_refine}` defined Task 5, used Task 7 ✓
- `theme_pipeline.{cluster_stats,select_clusters_to_split,stop_reason,current_k,grow}` defined Task 7, tested Task 7 ✓
- `cluster_claims.seed_phase(conn, sample_size, k, run_id, all_claims=False)` signature change (Task 3) matches the orchestrator call (Task 7) ✓

**Scope check:** single subsystem (the embedding theme-clustering pipeline); the graph-cluster/Louvain subsystem and any scheduling are explicitly out of scope. Plannable as one unit.
