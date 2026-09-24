#!/usr/bin/env bash
# D1 e2e: the SEVEN callers of `McpEmbedder::embed_and_store` that the branch's
# first revision did not cover. These embed claims the INGEST EXECUTOR authored
# (`get_or_create_system_agent`), not claims authored by the MCP server's agent,
# so they are the arms that distinguish "the embedder is stamped" from "the
# embedder is stamped FROM THE RIGHT AUTHOR".
#
#   ./probe-embed.sh <binary> <label> <a|b>
#
# Same transport, role, database and advisory lock as run-e2e.sh / probe-tools.sh.
#
# Credentials from the environment (see run-e2e.sh's header):
#   E2E_SU_DSN, E2E_APP_DSN, OPENAI_API_KEY (required: without a key the embedder
#   fails BEFORE touching the database and `embedding IS NOT NULL` proves nothing).
# Optional:
#   E2E_AGENT_KEY   32-byte hex Ed25519 seed for the MCP server's own agent
#                   identity. Defaults to the throwaway seed below. DO NOT point
#                   this at a real deployment's key: an earlier revision of this
#                   harness inlined the LIVE production `epigraph-mcp-http.service`
#                   / `epigraph-mcp-auth.service` `--agent-key`, which is why it is
#                   a parameter with a deliberately public default. Any 32 bytes is
#                   a valid Ed25519 seed; the harness only needs it stable within
#                   one run, and it writes to a throwaway database.
: "${E2E_SU_DSN:?set E2E_SU_DSN}"
: "${E2E_APP_DSN:?set E2E_APP_DSN}"
# Refuse a DSN on the production port (or with no port) before anything runs;
# sets E2E_SU_PORT, which every psql call below passes as -p.
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
set -uo pipefail
BIN="${1:?usage: probe-embed.sh <binary> <label> <a|b>}"
LABEL="${2:?label}"
CFG="${3:?a|b}"
E2E="$(cd "$(dirname "$0")" && pwd)"
SOCK="$E2E/embed.sock.$LABEL"
H=(-H Content-Type:application/json -H Accept:application/json,text/event-stream)

SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
SU_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
q() { PGPASSWORD="$SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$SU_USER" -d "$SU_DB" -tA -c "$1"; }
E2E_AGENT_KEY="${E2E_AGENT_KEY:-000000000000000000000000000000000000000000000000000000000e2e5eed}"

# OPENAI_API_KEY comes from the ENVIRONMENT only. An earlier revision read it out
# of a host-specific `epiclaw.env`, which made the harness unrunnable anywhere else
# and pulled a live credential into a path this script does not own.
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
[ -n "${OPENAI_API_KEY:-}" ] || { echo "FAIL: no OPENAI_API_KEY; every arm would be vacuous"; exit 1; }

echo "### binary: $BIN"
LOCKFIFO="$E2E/.elock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$SU_USER" -d "$SU_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"
release_lock() { exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO"; }
echo "### serialized on advisory lock 918273645"

"$E2E/set-config.sh" "$CFG" >/dev/null 2>&1
echo "### $(q "SELECT 'config: ' || CASE WHEN EXISTS(SELECT 1 FROM pg_policy WHERE polname='claims_privacy') THEN 'B (prod-faithful)' ELSE 'A (clean series)' END")"
q "TRUNCATE claims, evidence, edges, reasoning_traces, mass_functions, claim_frames, recall_events, challenges, events, workflows CASCADE;" >/dev/null 2>&1

rm -f "$SOCK"
DATABASE_URL="$E2E_APP_DSN" OPENAI_API_KEY="$OPENAI_API_KEY" RUST_LOG=warn "$BIN" \
  --agent-key "$E2E_AGENT_KEY" \
  --listen "unix:$SOCK" --allow-unauthenticated-http > "$E2E/embed.$LABEL.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; release_lock' EXIT
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 1; done
[ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -20 "$E2E/embed.$LABEL.log"; exit 1; }

call() { curl -s --unix-socket "$SOCK" "${H[@]}" -H "mcp-session-id: $SID" \
           -X POST http://localhost/mcp -d "$1" | grep '^data: {' | tail -1; }

curl -s --unix-socket "$SOCK" "${H[@]}" -X POST http://localhost/mcp -D "$E2E/eh.$LABEL" -o /dev/null \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"embed-probe","version":"1"}}}'
SID=$(grep -i '^mcp-session-id:' "$E2E/eh.$LABEL" | tr -d '\r' | cut -d' ' -f2)
call '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

WF="probe-wf-$LABEL"
echo "--- store_workflow (executor-authored step claims) ---"
SW=$(call "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"store_workflow\",\"arguments\":{\"goal\":\"Probe the embedder store path for executor-authored claims\",\"steps\":[\"Take a measurement of the embedding column\",\"Compare it against the claim author group\"],\"canonical_name\":\"$WF\"}}}")
echo "$SW" | tail -c 300
echo
# store_workflow SLUGIFIES canonical_name from the goal, so the name to address
# `add_step` with is the one it returns, not the one that was sent. Reading it
# back is the difference between exercising `add_step` and getting an
# invalid_params that proves nothing.
CANON=$(echo "$SW" | grep -oE '"canonical_name\\": \\"[a-z0-9-]+' | head -1 | sed 's/.*\\"//')
echo "--- add_step on '${CANON:-$WF}' (AddStepResult::inserted_content path) ---"
call "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"add_step\",\"arguments\":{\"canonical_name\":\"${CANON:-$WF}\",\"step_text\":\"Record whether the third step also carries a vector\"}}}" | tail -c 300
echo

# LABEL SPELLING IS `workflow_step`, WITH AN UNDERSCORE. An earlier revision of
# this script asked for `workflow-step` with a hyphen, which matches nothing, so
# every line below read `step_claims=0` and the whole D1 verdict was VACUOUS while
# looking like a measurement. The executor writes `workflow_thesis` /
# `workflow_step` (verified directly against the seeded rows). If these counts come
# back 0, check the labels before concluding anything about the embedder.
echo "=== THE VERDICT: who authored the step claims, and do they carry a vector ==="
q "SELECT 'author_is_system_agent=' ||
          (SELECT count(DISTINCT c.agent_id) FROM claims c WHERE 'workflow_step' = ANY(c.labels))
       || ' step_claims=' || (SELECT count(*) FROM claims WHERE 'workflow_step' = ANY(labels))
       || ' step_claims_embedded=' ||
          (SELECT count(*) FROM claims WHERE 'workflow_step' = ANY(labels) AND embedding IS NOT NULL)
       || ' all_claims=' || (SELECT count(*) FROM claims)
       || ' all_embedded=' || (SELECT count(*) FROM claims WHERE embedding IS NOT NULL)"
echo "--- author of the step claims vs the MCP server's own agent ---"
q "SELECT DISTINCT 'step author group=' || COALESCE(c.owner_group_id::text,'NULL')
     FROM claims c WHERE 'workflow_step' = ANY(c.labels)"
echo "=== WARN / refusal lines ==="
grep -iE "42501|row-level|scoped_write|refus|embedding" "$E2E/embed.$LABEL.log" | tail -12
echo "(no lines above = no embedding failure was warned)"
