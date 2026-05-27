#!/usr/bin/env python3
"""Assessment queue worker -- drains pending assessment_queue entries with tiered enrichment.

Queries assessment_queue for pending (or failed) entries ordered by conflict_k DESC,
runs auto_tier() enrichment on each claim, and marks entries completed.

Usage:
    # Process up to 10 pending assessments (default)
    python3 scripts/run_assessment_worker.py

    # Process more
    python3 scripts/run_assessment_worker.py --limit 25

    # Dry run (show what would be processed, don't write)
    python3 scripts/run_assessment_worker.py --dry-run

    # Also retry previously failed assessments
    python3 scripts/run_assessment_worker.py --retry-failed

    # Combine flags
    python3 scripts/run_assessment_worker.py --dry-run --limit 5 --retry-failed
"""

import argparse
import asyncio
import json
import logging
import os
import sys

import psycopg2

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from lib.tiered_enrichment import auto_tier, EnrichmentResult

log = logging.getLogger(__name__)

# Read-only DB for all SELECT queries
DATABASE_RO_URL = os.environ.get(
    "DATABASE_URL",
    "postgres://epigraph_ro:epigraph_ro@localhost:5432/epigraph",
)
# Admin DB for UPDATE assessment_queue (status transitions only)
DATABASE_ADMIN_URL = os.environ.get(
    "DATABASE_ADMIN_URL",
    "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph",
)
API_URL = os.environ.get("EPIGRAPH_API_URL", "http://127.0.0.1:8080")

# Threshold at which has_conflict=True is set for auto_tier()
CONFLICT_THRESHOLD = 0.3
MAX_SURROUNDING = 5
MAX_CROSS_SOURCE = 10


# -- Database helpers ----------------------------------------------------------

def psql_query(sql: str, params: tuple = (), database_url: str = DATABASE_RO_URL) -> list:
    """Run a parameterized SELECT, return rows as tuples of strings (psql-compatible shape).

    Values are coerced to str (or None) to preserve the legacy psql `-t -A` text output
    contract the rest of this script was written against.
    """
    try:
        conn = psycopg2.connect(database_url)
    except psycopg2.Error as e:
        log.error("psycopg2 connect error: %s", e)
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            raw_rows = cur.fetchall()
    except psycopg2.Error as e:
        log.error("psycopg2 query error: %s", e)
        return []
    finally:
        conn.close()

    rows = []
    for raw in raw_rows:
        rows.append(tuple(None if v is None else str(v) for v in raw))
    return rows


def psql_exec(sql: str, params: tuple = ()) -> bool:
    """Execute a parameterized write via epigraph_admin. Returns True on success."""
    try:
        conn = psycopg2.connect(DATABASE_ADMIN_URL)
    except psycopg2.Error as e:
        log.error("psycopg2 admin connect error: %s", e)
        return False
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()
        return True
    except psycopg2.Error as e:
        log.error("psycopg2 exec error: %s", e)
        conn.rollback()
        return False
    finally:
        conn.close()


# -- Queue queries -------------------------------------------------------------

def get_pending_assessments(limit: int, include_failed: bool) -> list:
    """Fetch pending (and optionally failed) assessment_queue entries."""
    if include_failed:
        statuses = ("pending", "failed")
    else:
        statuses = ("pending",)

    sql = """
    SELECT id::text, claim_id::text, trigger, conflict_k::text, k_band
    FROM assessment_queue
    WHERE status = ANY(%s)
    ORDER BY conflict_k DESC
    LIMIT %s
    """
    rows = psql_query(sql, (list(statuses), limit))
    entries = []
    for parts in rows:
        if len(parts) >= 5:
            entries.append({
                "id": parts[0],
                "claim_id": parts[1],
                "trigger": parts[2],
                "conflict_k": float(parts[3]) if parts[3] else 0.0,
                "k_band": parts[4],
            })
    return entries


# -- Claim context fetchers ----------------------------------------------------

def get_claim_content(claim_id: str) -> str:
    """Fetch the text content of a claim."""
    sql = "SELECT content FROM claims WHERE id = %s::uuid LIMIT 1"
    rows = psql_query(sql, (claim_id,))
    if rows and rows[0][0]:
        return rows[0][0]
    return None


def get_claim_doi(claim_id: str) -> str:
    """Fetch the source_doi property for a claim."""
    sql = """
    SELECT properties->>'source_doi'
    FROM claims
    WHERE id = %s::uuid
    LIMIT 1
    """
    rows = psql_query(sql, (claim_id,))
    if rows and rows[0][0]:
        return rows[0][0]
    return None


def get_paper_abstract(doi: str) -> str:
    """Fetch paper abstract from the papers table."""
    if not doi:
        return ""
    sql = "SELECT abstract_text FROM papers WHERE doi = %s LIMIT 1"
    rows = psql_query(sql, (doi,))
    return rows[0][0] if rows and rows[0][0] else ""


def get_surrounding_claims(claim_id: str) -> list:
    """Fetch content of claims connected via structural edges for context."""
    sql = """
    SELECT LEFT(c2.content, 200)
    FROM edges e
    JOIN claims c2 ON c2.id = CASE
        WHEN e.source_id = %s THEN e.target_id::uuid
        ELSE e.source_id::uuid END
    WHERE (e.source_id = %s OR e.target_id = %s)
      AND e.source_type = 'claim' AND e.target_type = 'claim'
      AND e.relationship IN ('supports', 'contradicts', 'refines', 'decomposes_to', 'continues_argument')
    LIMIT %s
    """
    rows = psql_query(sql, (claim_id, claim_id, claim_id, MAX_SURROUNDING))
    return [r[0] for r in rows if r[0]]


def get_cross_source_history(claim_id: str) -> list:
    """Fetch cross-source corroboration/contradiction edges for Tier 3."""
    sql = """
    SELECT e.relationship, LEFT(c2.content, 200) AS other_content,
           c2.truth_value::text
    FROM edges e
    JOIN claims c2 ON c2.id = CASE
        WHEN e.source_id = %s THEN e.target_id::uuid
        ELSE e.source_id::uuid END
    WHERE (e.source_id = %s OR e.target_id = %s)
      AND e.source_type = 'claim' AND e.target_type = 'claim'
      AND e.relationship IN ('CORROBORATES', 'contradicts', 'CONTRADICTS')
    LIMIT %s
    """
    rows = psql_query(sql, (claim_id, claim_id, claim_id, MAX_CROSS_SOURCE))
    return [
        {"relationship": r[0], "content": r[1], "truth": float(r[2]) if r[2] else 0.5}
        for r in rows if len(r) >= 3
    ]


def get_ds_belief_state(claim_id: str) -> dict:
    """Fetch the latest Dempster-Shafer mass function for a claim."""
    sql = """
    SELECT masses::text, conflict_k::text, combination_method
    FROM mass_functions
    WHERE claim_id = %s::uuid
    ORDER BY created_at DESC
    LIMIT 1
    """
    rows = psql_query(sql, (claim_id,))
    if not rows or len(rows[0]) < 3:
        return {}
    try:
        return {
            "masses": json.loads(rows[0][0]),
            "conflict_k": float(rows[0][1]) if rows[0][1] else 0.0,
            "method": rows[0][2] or "dempster",
        }
    except (json.JSONDecodeError, ValueError):
        return {}


# -- Queue status transitions --------------------------------------------------

def set_assessment_status(queue_id: str, status: str) -> bool:
    """Update assessment_queue status. Uses epigraph_admin role."""
    sql = """
    UPDATE assessment_queue
    SET status = %s
    WHERE id = %s::uuid
    """
    return psql_exec(sql, (status, queue_id))


# -- API interaction -----------------------------------------------------------

def _acquire_token() -> str:
    """Get a bearer token via client_credentials grant."""
    import urllib.request

    token_req = urllib.request.Request(
        "{api}/oauth/token".format(api=API_URL),
        data=json.dumps({
            "grant_type": "client_credentials",
            "client_id": os.environ.get("EPIGRAPH_SERVICE_CLIENT_ID", "epiclaw-agent-service"),
            "client_secret": os.environ.get("EPIGRAPH_SERVICE_SECRET", ""),
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(token_req, timeout=10) as resp:
            return json.loads(resp.read())["access_token"]
    except Exception as e:
        log.error("Token acquisition failed: %s", e)
        return None


def add_claim_label(claim_id: str, tier: int, token: str) -> bool:
    """Add enrichment:tierN_complete label to a claim via the API."""
    import urllib.request

    tier_label = "enrichment:tier{t}_complete".format(t=tier)
    label_req = urllib.request.Request(
        "{api}/api/v1/claims/{cid}/labels".format(api=API_URL, cid=claim_id),
        data=json.dumps({
            "add": [tier_label],
        }).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer {tok}".format(tok=token),
        },
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(label_req, timeout=10):
            return True
    except Exception as e:
        log.error("Label update failed for %s: %s", claim_id[:8], e)
        return False


# -- Core processing -----------------------------------------------------------

async def process_entry(entry: dict, dry_run: bool, token) -> bool:
    """Process a single assessment_queue entry. Returns True on success."""
    claim_id = entry["claim_id"]
    queue_id = entry["id"]
    conflict_k = entry["conflict_k"]

    log.info(
        "Processing queue entry %s -> claim %s (conflict_k=%.3f, band=%s, trigger=%s)",
        queue_id[:8], claim_id[:8], conflict_k, entry["k_band"], entry["trigger"],
    )

    # Fetch claim content
    content = get_claim_content(claim_id)
    if not content:
        log.warning("Claim %s not found or has no content -- skipping", claim_id[:8])
        if not dry_run:
            set_assessment_status(queue_id, "skipped")
        return False

    # Fetch paper abstract via source_doi
    doi = get_claim_doi(claim_id)
    abstract = get_paper_abstract(doi) if doi else ""

    # Fetch surrounding claims (structural edges, limit 5)
    surrounding = get_surrounding_claims(claim_id)

    # Fetch cross-source history (CORROBORATES/contradicts, limit 10)
    cross_source = get_cross_source_history(claim_id)

    # Fetch DS belief state (latest mass_function)
    ds_state = get_ds_belief_state(claim_id)

    if dry_run:
        log.info(
            "[DRY RUN] Would enrich claim %s: abstract=%s, %d surrounding, "
            "%d cross-source, ds_state=%s",
            claim_id[:8],
            "yes" if abstract else "no",
            len(surrounding),
            len(cross_source),
            "present" if ds_state else "absent",
        )
        return True

    # Mark as 'assessing' before LLM call
    if not set_assessment_status(queue_id, "assessing"):
        log.error("Failed to set status=assessing for queue entry %s", queue_id[:8])
        return False

    # Run auto_tier with full context
    has_conflict = conflict_k >= CONFLICT_THRESHOLD
    try:
        result = await auto_tier(
            claim_text=content,
            evidence_text=content,   # Claim is its own primary evidence unit
            has_conflict=has_conflict,
            abstract=abstract or content[:500],
            surrounding_sentences=surrounding,
            cross_source_history=cross_source,
            ds_belief_state=ds_state,
        )
    except Exception as e:
        log.error("auto_tier failed for claim %s: %s", claim_id[:8], e)
        set_assessment_status(queue_id, "failed")
        return False

    log.info(
        "Enrichment result for %s: tier=%d methodology=%s confidence=%.2f supports=%s",
        claim_id[:8], result.tier, result.methodology, result.confidence, result.supports_claim,
    )

    # Add enrichment label via API
    if token and not add_claim_label(claim_id, result.tier, token):
        log.warning("Label add failed for %s -- still marking completed", claim_id[:8])

    # Mark queue entry as 'completed'
    if not set_assessment_status(queue_id, "completed"):
        log.error("Failed to set status=completed for queue entry %s", queue_id[:8])
        return False

    return True


async def main():
    parser = argparse.ArgumentParser(description="Assessment queue worker with tiered enrichment")
    parser.add_argument("--limit", type=int, default=10, help="Max assessments to process per run")
    parser.add_argument("--dry-run", action="store_true", help="Show pending entries without processing")
    parser.add_argument("--retry-failed", action="store_true", help="Also retry previously failed entries")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    entries = get_pending_assessments(args.limit, include_failed=args.retry_failed)

    if not entries:
        print("TASK_SILENT")
        return

    log.info(
        "Found %d assessment queue entries to process (retry_failed=%s)",
        len(entries), args.retry_failed,
    )

    # Acquire bearer token once for all label updates (skip in dry-run)
    token = None
    if not args.dry_run:
        token = _acquire_token()
        if not token:
            log.warning("Could not acquire API token -- label updates will be skipped")

    processed = 0
    failed = 0
    for entry in entries:
        success = await process_entry(entry, args.dry_run, token)
        if success:
            processed += 1
        else:
            failed += 1

    if args.dry_run:
        log.info("Dry run complete: %d entries would be processed", processed)
    else:
        log.info("Assessment worker complete: %d succeeded, %d failed", processed, failed)

    if processed == 0 and failed == 0:
        print("TASK_SILENT")


if __name__ == "__main__":
    asyncio.run(main())
