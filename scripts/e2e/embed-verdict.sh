#!/usr/bin/env bash
# The D1 verdict the row-count line in run-e2e.sh cannot see: how many of the
# claims this run committed actually carry a vector.
# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB (migrations,
#                policy replay, row counts).  e.g. postgres://u:p@host:5432/epigraph_e2e_test
#   E2E_APP_DSN  the least-privilege application DSN the server connects as.
#                MUST be a role with rolbypassrls=false, or every arm is vacuous.
# Optional:
#   OPENAI_API_KEY  required for the D1 embedding arm; without it the embedder
#                   fails before touching the DB and `embedded:` proves nothing.
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
# -----------------------------------------------------------------------------
export PGPASSWORD="$E2E_SU_PW"
psql -h 127.0.0.1 -U "$E2E_SU_USER" -d "$E2E_DB" -tA -c \
  "SELECT 'embedded=' || count(*) FILTER (WHERE embedding IS NOT NULL) || '/' || count(*) AS embeddings
     FROM claims"
