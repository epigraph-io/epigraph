#!/usr/bin/env bash
# Tool-level e2e probe for the tools PR #494 did NOT convert:
# challenge_claim, update_with_evidence, submit_ds_evidence, deprecate_workflow's
# claim writes, and add_step/delete_step.
#
#   ./probe-tools.sh <binary> <label> <a|b>
#
# Same transport, same role and same throwaway database as run-e2e.sh (the real
# binary over a unix socket as `epigraph_app` against `epigraph_e2e_test`), and it
# takes the SAME advisory lock, because it truncates a shared database and then
# counts rows. The schema configuration is switched INSIDE the lock so a
# concurrent run cannot flip it underneath this one.
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
BIN="${1:?usage: probe-tools.sh <binary> <label> <a|b>}"
LABEL="${2:?label}"
CFG="${3:?a|b}"
E2E="$(cd "$(dirname "$0")" && pwd)"
SOCK="$E2E/probe.sock.$LABEL"
# The app DSN comes from the environment. An earlier revision read it from a
# sibling `dsn` FILE holding a real credential -- which both leaked it and made
# this script depend on a file that could not be committed alongside it.
DSN="$E2E_APP_DSN"
H=(-H Content-Type:application/json -H Accept:application/json,text/event-stream)

q() { PGPASSWORD="$E2E_SU_PW" psql -h 127.0.0.1 -U "$E2E_SU_USER" -d "$E2E_DB" -tA -c "$1"; }

# OPENAI_API_KEY comes from the ENVIRONMENT only. An earlier revision read it out
# of a host-specific `epiclaw.env`, which made the harness unrunnable anywhere else
# and pulled a live credential into a path this script does not own.
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"

echo "### binary: $BIN"
LOCKFIFO="$E2E/.plock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$E2E_SU_PW" \
  psql -h 127.0.0.1 -U "$E2E_SU_USER" -d "$E2E_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"
release_lock() { exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO"; }
echo "### serialized on advisory lock 918273645"

"$E2E/set-config.sh" "$CFG"
# `events` is truncated too, unlike run-e2e.sh: `claim.challenged` is one of the
# things this probe counts, and without it the count is cumulative across runs.
q "TRUNCATE claims, evidence, edges, reasoning_traces, mass_functions, claim_frames, recall_events, challenges, events CASCADE;" >/dev/null

rm -f "$SOCK"
DATABASE_URL="$DSN" RUST_LOG=warn "$BIN" \
  --agent-key "$E2E_AGENT_KEY" \
  --listen "unix:$SOCK" --allow-unauthenticated-http > "$E2E/probe.$LABEL.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; release_lock' EXIT
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 1; done
[ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -20 "$E2E/probe.$LABEL.log"; exit 1; }

call() { curl -s --unix-socket "$SOCK" "${H[@]}" -H "mcp-session-id: $SID" \
           -X POST http://localhost/mcp -d "$1" | grep '^data: {' | tail -1; }

curl -s --unix-socket "$SOCK" "${H[@]}" -X POST http://localhost/mcp -D "$E2E/ph.$LABEL" -o /dev/null \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}'
SID=$(grep -i '^mcp-session-id:' "$E2E/ph.$LABEL" | tr -d '\r' | cut -d' ' -f2)
call '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

# The claim every arm below hangs off. Authored by the MCP server's own agent, so
# it is owned by that agent's personal group — the shape production writes.
SUB=$(call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"submit_claim","arguments":{"content":"Probe parent claim for the unconverted tools","methodology":"extraction","evidence_data":"probe-parent","evidence_type":"empirical","confidence":0.9,"novelty_threshold":0.0}}}')
CLAIM=$(echo "$SUB" | grep -oE '"claim_id\\": \\"[0-9a-f-]{36}' | head -1 | grep -oE '[0-9a-f-]{36}')
echo "--- parent claim: ${CLAIM:-NONE} ---"
[ -n "${CLAIM:-}" ] || { echo "FAIL: no parent claim; submit_claim said: $SUB"; exit 1; }

echo "--- challenge_claim ---"
call "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"challenge_claim\",\"arguments\":{\"claim_id\":\"$CLAIM\",\"challenge_type\":\"insufficient_evidence\",\"explanation\":\"probe challenge\"}}}" | tail -c 400
echo
echo "--- update_with_evidence ---"
# `labels` is passed so the arm has a DISCRIMINATING row count. The evidence
# INSERT commits before the DS wiring on every binary, so `evidence` alone reads
# the same whether the tool then errors or succeeds; the label merge runs only
# AFTER the wiring, so `uwe_labelled` separates "errored after the evidence row"
# from "completed". The snapshot is taken HERE, before submit_ds_evidence below
# can add frames/masses of its own.
TRUTH_PRE=$(q "SELECT truth_value FROM claims WHERE id = '$CLAIM'")
UWE=$(call "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"update_with_evidence\",\"arguments\":{\"claim_id\":\"$CLAIM\",\"evidence_data\":\"probe corroboration\",\"evidence_type\":\"empirical\",\"strength\":0.7,\"supports\":true,\"labels\":[\"uwe-probe\"]}}}")
echo "$UWE" | tail -c 500
echo
UWE_EV=$(echo "$UWE" | grep -oE '"evidence_id\\": \\"[0-9a-f-]{36}' | head -1 | grep -oE '[0-9a-f-]{36}')
echo "=== update_with_evidence snapshot ==="
q "SELECT 'evidence_on_claim='||(SELECT count(*) FROM evidence WHERE claim_id = '$CLAIM')
        ||' reported_evidence_attached='||(SELECT count(*) FROM evidence
             WHERE id::text = '${UWE_EV:-none}' AND claim_id = '$CLAIM')
        ||' claim_frames='||(SELECT count(*) FROM claim_frames)
        ||' mass_functions='||(SELECT count(*) FROM mass_functions)
        ||' uwe_labelled='||(SELECT count(*) FROM claims WHERE 'uwe-probe' = ANY(labels))
        ||' truth_value='||'$TRUTH_PRE'||'->'||(SELECT truth_value FROM claims WHERE id = '$CLAIM')"
echo "--- submit_ds_evidence (on the auto-wired binary_truth frame) ---"
FRAME=$(q "SELECT id FROM frames WHERE name = 'binary_truth' LIMIT 1")
if [ -n "$FRAME" ]; then
  call "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"submit_ds_evidence\",\"arguments\":{\"claim_id\":\"$CLAIM\",\"frame_id\":\"$FRAME\",\"masses\":{\"true\":0.6,\"true,false\":0.4},\"hypothesis_index\":0,\"reliability\":0.9}}}" | tail -c 500
else
  echo "(no binary_truth frame seeded; skipped)"
fi
echo

echo "--- update_labels (an UPDATE claims, same class as deprecate_workflow's) ---"
call "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"update_labels\",\"arguments\":{\"claim_id\":\"$CLAIM\",\"add\":[\"probe-label\"]}}}" | tail -c 300
echo

echo "=== ROW COUNTS ==="
q "SELECT 'claims='||(SELECT count(*) FROM claims)
        ||' evidence='||(SELECT count(*) FROM evidence)
        ||' challenges='||(SELECT count(*) FROM challenges)
        ||' events_challenged='||(SELECT count(*) FROM events WHERE event_type='claim.challenged')
        ||' claim_frames='||(SELECT count(*) FROM claim_frames)
        ||' mass_functions='||(SELECT count(*) FROM mass_functions)
        ||' labelled='||(SELECT count(*) FROM claims WHERE 'probe-label' = ANY(labels))"
echo "=== WARN / refusal lines ==="
grep -iE "42501|row-level|scoped_write|refus" "$E2E/probe.$LABEL.log" | tail -12
