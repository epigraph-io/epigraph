#!/usr/bin/env bash
# Switch `epigraph_e2e_test` between the two schema configurations the write
# path must be measured on. Written 2026-09-23; run-e2e.sh has referenced this
# file since it was authored, but it did not exist on disk.
#
#   CONFIG A  the clean public migration series (001 -> 101), nothing else.
#   CONFIG B  A + the three orphan PERMISSIVE *_privacy policies and the two
#             helper functions they call, replayed verbatim from production
#             (captured from the live definitions with pg_get_expr).
#
# The B definitions are reproduced here EXACTLY as pg_policy held them, including
# the absence of an explicit WITH CHECK (a `FOR ALL USING (...)` silently reuses
# USING as WITH CHECK — which is the whole reason these policies admit unstamped
# writes: `epigraph_current_group_id()` reads `app.group_id`, a GUC namespace
# nothing in this codebase sets, so it returns NULL and the check degenerates to
# TRUE).
#
#   ./set-config.sh a|b
# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB (migrations,
#                policy replay, row counts).  e.g. postgres://u:p@127.0.0.1:5433/epigraph_e2e_test
#                (an explicit port is required; a DSN on 5432 is refused)
#   E2E_APP_DSN  the least-privilege application DSN the server connects as.
#                MUST be a role with rolbypassrls=false, or every arm is vacuous.
# Optional:
#   OPENAI_API_KEY  required for the D1 embedding arm; without it the embedder
#                   fails before touching the DB and `embedded:` proves nothing.
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
# Refuse a DSN on the production port (or with no port) before anything runs;
# sets E2E_SU_PORT, which every psql call below passes as -p.
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
# -----------------------------------------------------------------------------
set -euo pipefail
WANT="${1:?usage: set-config.sh a|b}"
export PGPASSWORD="$E2E_SU_PW"
q() { psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -v ON_ERROR_STOP=1 -tA -c "$1"; }

case "${WANT,,}" in
  a)
    q "DROP POLICY IF EXISTS claims_privacy   ON claims;
       DROP POLICY IF EXISTS evidence_privacy ON evidence;
       DROP POLICY IF EXISTS edges_privacy    ON edges;" >/dev/null
    ;;
  b)
    q "$(cat "$(dirname "$0")/helper.sql")" >/dev/null
    q "$(cat "$(dirname "$0")/fn2.sql")"    >/dev/null
    q "DROP POLICY IF EXISTS claims_privacy ON claims;
       CREATE POLICY claims_privacy ON claims FOR ALL TO PUBLIC
         USING (epigraph_is_visible_to_group(id, 'claim'::text));
       DROP POLICY IF EXISTS evidence_privacy ON evidence;
       CREATE POLICY evidence_privacy ON evidence FOR ALL TO PUBLIC
         USING (epigraph_is_visible_to_group(id, 'evidence'::text));
       DROP POLICY IF EXISTS edges_privacy ON edges;
       CREATE POLICY edges_privacy ON edges FOR ALL TO PUBLIC
         USING (epigraph_is_visible_to_group(source_id, 'claim'::text)
            AND epigraph_is_visible_to_group(source_id, 'evidence'::text)
            AND epigraph_is_visible_to_group(target_id, 'claim'::text)
            AND epigraph_is_visible_to_group(target_id, 'evidence'::text));" >/dev/null
    ;;
  *) echo "usage: set-config.sh a|b" >&2; exit 2 ;;
esac

q "SELECT 'now on config: ' || CASE WHEN EXISTS(SELECT 1 FROM pg_policy WHERE polname='claims_privacy')
         THEN 'B (prod-faithful)' ELSE 'A (clean series)' END"
