#!/usr/bin/env bash
# E2E harness for the MCP write path, against a THROWAWAY database.
#
# Runs the real epigraph-mcp binary over a unix socket (so --allow-unauthenticated-http
# is accepted and no OAuth is needed), connecting as the real least-privilege role
# `epigraph_app`, against `epigraph_e2e_test`. Touches NO production service.
#
#   ./run-e2e.sh <path-to-epigraph-mcp-binary> [label]
#
# Two schema configurations matter:
#   CONFIG A  the clean public migration series (001->head)
#   CONFIG B  A + the three orphan *_privacy policies and their two helper functions,
#             replayed from prod. This is what production actually runs.
# Use ./set-config.sh a|b to switch.

# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB (migrations,
#                policy replay, row counts).  e.g. postgres://u:p@host:5432/epigraph_e2e_test
#   E2E_APP_DSN  the least-privilege application DSN the server connects as.
#                MUST be a role with rolbypassrls=false, or every arm is vacuous.
# Optional:
#   OPENAI_API_KEY  required for the D1 embedding arm; without it the embedder
#                   fails before touching the DB and `embedded:` proves nothing.
# Optional:
#   E2E_AGENT_KEY   32-byte hex Ed25519 seed for the MCP server's own agent
#                   identity. Defaults to the throwaway seed below. DO NOT point
#                   this at a real deployment's key: an earlier revision of this
#                   harness inlined the LIVE production `epigraph-mcp-http.service`
#                   / `epigraph-mcp-auth.service` `--agent-key`, which is why it is
#                   a parameter with a deliberately public default. Any 32 bytes is
#                   a valid Ed25519 seed; the harness only needs it stable within
#                   one run, and it writes to a throwaway database.
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
E2E_AGENT_KEY="${E2E_AGENT_KEY:-000000000000000000000000000000000000000000000000000000000e2e5eed}"
# -----------------------------------------------------------------------------
set -uo pipefail
BIN="${1:?usage: run-e2e.sh <epigraph-mcp binary> [label]}"
LABEL="${2:-run}"
E2E="$(cd "$(dirname "$0")" && pwd)"
SOCK="$E2E/mcp.sock.$LABEL"
SU="$E2E_SU_DSN"
DSN="$E2E_APP_DSN"
H=(-H Content-Type:application/json -H Accept:application/json,text/event-stream)

q() { PGPASSWORD="$E2E_SU_PW" psql -h 127.0.0.1 -U "$E2E_SU_USER" -d "$E2E_DB" -tA -c "$1"; }

echo "### binary: $BIN"

# SERIALIZE. This script TRUNCATEs a SHARED database and then counts rows, so two
# concurrent runs silently corrupt each other's verdict — one truncating while the
# other counts looks exactly like "the write path is broken". Reviewers run in
# parallel, so the lock is load-bearing, not hygiene.
#
# A session-level advisory lock held by a dedicated psql held open for the whole
# run; the FIFO keeps that psql alive until we release it. Waiters block in
# pg_advisory_lock rather than racing.
LOCKFIFO="$E2E/.lock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$E2E_SU_PW" \
  psql -h 127.0.0.1 -U "$E2E_SU_USER" -d "$E2E_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"          # holds the psql (and thus the lock) open
release_lock() { exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO"; }
echo "### serialized on advisory lock 918273645"

echo "### $(q "SELECT 'config: ' || CASE WHEN EXISTS(SELECT 1 FROM pg_policy WHERE polname='claims_privacy') THEN 'B (prod-faithful)' ELSE 'A (clean series)' END")"

# truncate so each run counts only its own rows
q "TRUNCATE claims, evidence, edges, reasoning_traces, mass_functions, claim_frames, recall_events CASCADE;" >/dev/null

rm -f "$SOCK"
DATABASE_URL="$DSN" RUST_LOG=warn "$BIN" \
  --agent-key "$E2E_AGENT_KEY" \
  --listen "unix:$SOCK" --allow-unauthenticated-http > "$E2E/mcp.$LABEL.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; release_lock' EXIT
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 1; done
[ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -20 "$E2E/mcp.$LABEL.log"; exit 1; }

call() { curl -s --unix-socket "$SOCK" "${H[@]}" -H "mcp-session-id: $SID" \
           -X POST http://localhost/mcp -d "$1" | grep '^data: {' | tail -1; }

curl -s --unix-socket "$SOCK" "${H[@]}" -X POST http://localhost/mcp -D "$E2E/h.$LABEL" -o /dev/null \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}'
SID=$(grep -i '^mcp-session-id:' "$E2E/h.$LABEL" | tr -d '\r' | cut -d' ' -f2)
call '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

echo "--- control: system_stats ---"
call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"system_stats","arguments":{}}}' | tail -c 200
echo
echo "--- submit_claim ---"
call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"submit_claim","arguments":{"content":"E2E probe submit_claim","methodology":"extraction","evidence_data":"harness","evidence_type":"empirical","confidence":0.9}}}' | tail -c 400
echo
echo "--- memorize ---"
call '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"memorize","arguments":{"content":"E2E probe memorize"}}}' | tail -c 400
echo
echo "--- challenge_claim / update_with_evidence surfaces ---"
call '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"link_epistemic","arguments":{"source_claim_id":"00000000-0000-0000-0000-000000000001","target_claim_id":"00000000-0000-0000-0000-000000000002","relationship":"supports"}}}' | tail -c 300
echo
echo "=== ROW COUNTS (the actual verdict) ==="
q "SELECT 'claims='||(SELECT count(*) FROM claims)||' traces='||(SELECT count(*) FROM reasoning_traces)||' evidence='||(SELECT count(*) FROM evidence)||' edges='||(SELECT count(*) FROM edges)||' mass_functions='||(SELECT count(*) FROM mass_functions)"
echo
echo "PASS CRITERIA after the fix:"
echo "  submit_claim and memorize return success (no 42501)"
echo "  claims == traces == evidence (each submission wrote all three)"
echo "  and on an injected mid-transaction failure: claims == 0 (atomic rollback, NO orphan)"
