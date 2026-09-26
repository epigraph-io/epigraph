#!/usr/bin/env bash
# Unit E acceptance probe: every tool the R3 release gate names that the other
# probes do not already reach, measured on the real binary as the real
# least-privilege role.
#
#   ./probe-unit-e.sh <epigraph-mcp binary> <label> <a|b>
#
# For each tool it prints the tool's response AND the rows the database holds
# afterwards, because the gate is "succeeds, or fails LOUDLY AND ATOMICALLY" —
# a success-shaped response over zero rows, or an error over half-written rows,
# are both failures and only the row counts can tell them apart.
#
#   E1  ingest_workflow (with level-3 operation atoms, which is what reaches the
#       post-commit DS batch), improve_workflow_hierarchy, delete_step,
#       ingest_document_inline, consolidate_claims
#   E2  link_epistemic's belief wiring (`belief_wired`), and the atom BBAs the
#       workflow / document ingests wire
#
#   REVIEW  plan order under one transaction (report attribution), a SECOND
#           store_workflow on a non-empty database, transactional event
#           timestamps, a hidden axis frame inside the DS transaction, and a
#           server agent revoked in its PERSONAL group but live in a team group
#           (warm session, a fresh MCP session, and a restarted process)
#   BATCH F RECALL (#493): recall by a revoked principal does not revive it
#
# add_step and store_workflow are probe-embed.sh's; update_with_evidence and
# submit_ds_evidence are probe-tools.sh's; report_workflow_outcome and
# deprecate_workflow are probe-workflow.sh's.

# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB.
#   E2E_APP_DSN  the least-privilege application DSN the server connects as.
#                MUST be a role with rolbypassrls=false, or every arm is vacuous.
# Optional:
#   OPENAI_API_KEY  the embedder; every arm here treats it as best-effort.
#   E2E_AGENT_KEY   32-byte hex Ed25519 seed for the server's own agent. Defaults
#                   to a deliberately public throwaway seed; never a real key.
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
# Refuse a DSN on the production port (or with no port) before anything runs;
# sets E2E_SU_PORT, which every psql call below passes as -p.
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
E2E_AGENT_KEY="${E2E_AGENT_KEY:-000000000000000000000000000000000000000000000000000000000e2e5eed}"
# -----------------------------------------------------------------------------
set -uo pipefail
BIN="${1:?usage: probe-unit-e.sh <binary> <label> <a|b>}"
LABEL="${2:?label}"
CFG="${3:?a|b}"
E2E="$(cd "$(dirname "$0")" && pwd)"
SOCK="$E2E/ue.sock.$LABEL"
H=(-H Content-Type:application/json -H Accept:application/json,text/event-stream)
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"

q() { PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -tA -c "$1"; }

echo "### binary: $BIN"
# Serialized for the same reason as every other script here: TRUNCATE + count.
LOCKFIFO="$E2E/.uelock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"
release_lock() { exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO"; }
echo "### serialized on advisory lock 918273645"

"$E2E/set-config.sh" "$CFG" >/dev/null 2>&1
echo "### $(q "SELECT 'config: ' || CASE WHEN EXISTS(SELECT 1 FROM pg_policy WHERE polname='claims_privacy') THEN 'B (prod-faithful)' ELSE 'A (clean series)' END")"
q "TRUNCATE claims, evidence, edges, reasoning_traces, mass_functions, claim_frames,
           recall_events, challenges, events, workflows, papers CASCADE;" >/dev/null 2>&1

# Started by a function so the FRESH-PROCESS arm below can restart the server:
# a restart is the only thing that empties the process-wide agent-id cell
# (`SessionFactory`), so it is the only way to reach the provisioning call again.
start_server() {
  rm -f "$SOCK"
  DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
    --agent-key "$E2E_AGENT_KEY" \
    --listen "unix:$SOCK" --allow-unauthenticated-http >> "$E2E/ue.$LABEL.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 1; done
  [ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -20 "$E2E/ue.$LABEL.log"; exit 1; }
}
: > "$E2E/ue.$LABEL.log"
start_server
trap 'kill $PID 2>/dev/null; release_lock' EXIT

call() { curl -s --unix-socket "$SOCK" "${H[@]}" -H "mcp-session-id: $SID" \
           -X POST http://localhost/mcp -d "$1" | grep '^data: {' | tail -1; }
tool() {  # $1 = tool name, $2 = JSON arguments
  call "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"
}
uuid_of() {  # $1 = response, $2 = JSON key
  echo "$1" | grep -oE "\"$2\\\\\": \\\\\"[0-9a-f-]{36}" | head -1 | grep -oE '[0-9a-f-]{36}'
}

curl -s --unix-socket "$SOCK" "${H[@]}" -X POST http://localhost/mcp -D "$E2E/ueh.$LABEL" -o /dev/null \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"unit-e-probe","version":"1"}}}'
SID=$(grep -i '^mcp-session-id:' "$E2E/ueh.$LABEL" | tr -d '\r' | cut -d' ' -f2)
call '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

WF_CANON="ue-probe-$LABEL"
WF_EXTRACTION='{"source":{"canonical_name":"'"$WF_CANON"'","goal":"Probe the ingest executor on a clean schema","generation":0,"authors":[],"tags":[],"metadata":{}},"thesis":"The ingest executor lands whole or not at all","thesis_derivation":"TopDown","phases":[{"title":"Phase one","summary":"Ingest a workflow with operation atoms","steps":[{"compound":"Ingest the plan","rationale":"Reach the level-3 atoms","operations":["Write the operation atom claims","Wire a BBA for each operation atom"],"generality":[2,1],"confidence":0.9,"evidence_type":"empirical"}]}],"relationships":[]}'

echo
echo "=== E1: ingest_workflow ==="
R=$(tool ingest_workflow "{\"extraction\":$WF_EXTRACTION}")
echo "$R" | tail -c 400; echo
q "SELECT '   workflows='||(SELECT count(*) FROM workflows WHERE canonical_name='$WF_CANON')
        ||' claims='||(SELECT count(*) FROM claims)
        ||' executes_edges='||(SELECT count(*) FROM edges WHERE relationship='executes')
        ||' atom_bbas='||(SELECT count(*) FROM mass_functions m JOIN claims c ON c.id=m.claim_id
                           WHERE c.content LIKE 'Write the operation%' OR c.content LIKE 'Wire a BBA%')"

echo
echo "=== E1: improve_workflow_hierarchy (generation 1 over the one above) ==="
IMP_EXTRACTION=$(printf '%s' "$WF_EXTRACTION" | sed -e "s/\"generation\":0/\"generation\":1/" \
  -e "s/Write the operation atom claims/Write the improved operation atom claims/")
R=$(tool improve_workflow_hierarchy "{\"parent_canonical_name\":\"$WF_CANON\",\"extraction\":$IMP_EXTRACTION}")
echo "$R" | tail -c 400; echo
q "SELECT '   workflows='||(SELECT count(*) FROM workflows WHERE canonical_name='$WF_CANON')
        ||' variant_of='||(SELECT count(*) FROM edges WHERE relationship='variant_of')
        ||' claims='||(SELECT count(*) FROM claims)"

echo
echo "=== E1: delete_step (soft-delete one step of the generation-0 workflow) ==="
LIN=$(q "SELECT c.step_lineage_id FROM claims c JOIN edges e ON e.target_id=c.id
          JOIN workflows w ON w.id=e.source_id
         WHERE w.canonical_name='$WF_CANON' AND 'workflow_step'=ANY(c.labels)
           AND c.step_lineage_id IS NOT NULL LIMIT 1")
if [ -n "$LIN" ]; then
  R=$(tool delete_step "{\"canonical_name\":\"$WF_CANON\",\"step_lineage_id\":\"$LIN\"}")
  echo "$R" | tail -c 300; echo
  q "SELECT '   step truth_value='||COALESCE((SELECT string_agg(truth_value::text,',') FROM claims WHERE step_lineage_id='$LIN'),'n/a')"
else
  echo "   SKIP: no step lineage (the ingest above wrote nothing)"
fi

echo
echo "=== E2: link_epistemic supports (both endpoints the server agent's own) ==="
S1=$(tool submit_claim '{"content":"Unit E probe source claim for link_epistemic","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.8,"novelty_threshold":0.0}')
S2=$(tool submit_claim '{"content":"Unit E probe target claim for link_epistemic","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.6,"novelty_threshold":0.0}')
C1=$(uuid_of "$S1" claim_id); C2=$(uuid_of "$S2" claim_id)
echo "   source=${C1:-NONE} target=${C2:-NONE}"
if [ -n "$C1" ] && [ -n "$C2" ]; then
  MF_BEFORE=$(q "SELECT count(*) FROM mass_functions WHERE claim_id='$C2'")
  R=$(tool link_epistemic "{\"source_claim_id\":\"$C1\",\"target_claim_id\":\"$C2\",\"relationship\":\"supports\"}")
  echo "$R" | tail -c 400; echo
  q "SELECT '   target mass_functions before=$MF_BEFORE after='||(SELECT count(*) FROM mass_functions WHERE claim_id='$C2')
          ||' supports_edges='||(SELECT count(*) FROM edges WHERE relationship='supports' AND source_id='$C1')"
fi

echo
echo "=== REGISTER: alias-bound edge writes still on the unstamped pool (own PUBLIC claims) ==="
# residual_unstamped_writes.rs now follows `let pool = &server.pool;` bindings,
# which surfaced these. They are registered, not converted; this arm is the
# measurement their register reasons cite.
S4=$(tool submit_claim '{"content":"Unit E register probe parent","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"novelty_threshold":0.0}')
S5=$(tool submit_claim '{"content":"Unit E register probe child","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"novelty_threshold":0.0}')
C4=$(uuid_of "$S4" claim_id); C5=$(uuid_of "$S5" claim_id)
if [ -n "$C4" ] && [ -n "$C5" ]; then
  R=$(tool link_hierarchical "{\"source_claim_id\":\"$C4\",\"target_claim_id\":\"$C5\",\"relationship\":\"decomposes_to\"}")
  echo "   link_hierarchical: $(echo "$R" | grep -oE '"isError":(true|false)|"message":"[^"]{0,160}' | head -1)"
  R=$(tool link_alternative "{\"claim_a\":\"$C4\",\"claim_b\":\"$C5\"}")
  echo "   link_alternative:  $(echo "$R" | grep -oE '"isError":(true|false)|"message":"[^"]{0,160}' | head -1)"
  EID=$(q "SELECT id FROM edges WHERE source_id='$C4' AND target_id='$C5' AND relationship='decomposes_to' LIMIT 1")
  R=$(tool patch_edge "{\"edge_id\":\"$EID\",\"properties\":{\"probe\":true}}")
  echo "   patch_edge:        $(echo "$R" | grep -oE '"isError":(true|false)|"message":"[^"]{0,160}' | head -1)"
  R=$(tool delete_edge "{\"edge_id\":\"$EID\"}")
  echo "   delete_edge:       $(echo "$R" | grep -oE '"isError":(true|false)|"message":"[^"]{0,160}' | head -1)"
  q "SELECT '   edges: decomposes_to='||(SELECT count(*) FROM edges WHERE source_id='$C4' AND relationship='decomposes_to')
          ||' in_force='||(SELECT count(*) FROM edges WHERE source_id='$C4' AND relationship='decomposes_to' AND valid_to IS NULL)
          ||' patched='||(SELECT count(*) FROM edges WHERE id='$EID' AND properties ? 'probe')
          ||' alternative_of='||(SELECT count(*) FROM edges WHERE relationship='alternative_of' AND (source_id IN ('$C4','$C5')))
          ||' owners='||COALESCE((SELECT string_agg(DISTINCT owner_group_id::text||'/'||visibility, ',') FROM edges WHERE source_id IN ('$C4','$C5') AND relationship IN ('decomposes_to','alternative_of')),'-')"
fi

echo
echo "=== E1: consolidate_claims (the two claims above, both the server agent's own) ==="
if [ -n "${C1:-}" ] && [ -n "${C2:-}" ]; then
  R=$(tool consolidate_claims "{\"source_claim_ids\":[\"$C1\",\"$C2\"],\"merged_content\":\"Unit E probe merged claim\",\"mode\":\"merge\",\"reason\":\"probe\"}")
  echo "$R" | tail -c 400; echo
  q "SELECT '   merged_rows='||(SELECT count(*) FROM claims WHERE content='Unit E probe merged claim')
          ||' sources_retired='||(SELECT count(*) FROM claims WHERE id IN ('$C1','$C2') AND supersedes IS NOT NULL)"

  echo "--- consolidate_claims FOREIGN: one own source + one PUBLIC source owned by another group ---"
  # Must fail LOUDLY AND ATOMICALLY: no merged row, neither source retired.
  S3=$(tool submit_claim '{"content":"Unit E probe own source for the foreign merge","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"novelty_threshold":0.0}')
  C3=$(uuid_of "$S3" claim_id)
  FA=$(q "SELECT agent_id FROM claims WHERE 'workflow_step' = ANY(labels) LIMIT 1")
  FG=$(q "SELECT owner_group_id FROM claims WHERE 'workflow_step' = ANY(labels) LIMIT 1")
  if [ -n "$C3" ] && [ -n "$FA" ] && [ -n "$FG" ]; then
    CF=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id)
            VALUES (gen_random_uuid(), 'Unit E probe foreign public source',
                    decode(md5(random()::text)||md5(random()::text),'hex'), 0.6, '$FA',
                    ARRAY['claim']::text[], 'public', '$FG') RETURNING id" | head -1)
    R=$(tool consolidate_claims "{\"source_claim_ids\":[\"$C3\",\"$CF\"],\"merged_content\":\"Unit E probe foreign merged claim\",\"mode\":\"merge\",\"reason\":\"probe\"}")
    echo "$R" | tail -c 300; echo
    q "SELECT '   merged_rows='||(SELECT count(*) FROM claims WHERE content='Unit E probe foreign merged claim')
            ||' sources_retired='||(SELECT count(*) FROM claims WHERE id IN ('$C3','$CF') AND (supersedes IS NOT NULL OR NOT is_current))"
  else
    echo "   SKIP: could not seed the foreign arm (own=$C3 foreign_agent=$FA foreign_group=$FG)"
  fi
fi

echo
echo "=== E1: ingest_document_inline (detached; polled) ==="
DOI="10.9999/unit-e-$LABEL"
DOC='{"source":{"title":"Unit E probe paper","doi":"'"$DOI"'","source_type":"Paper","authors":[{"name":"Probe Author","affiliations":[],"roles":["author"]}]},"thesis":"Unit E probe thesis about clean schemas","thesis_derivation":"TopDown","sections":[{"title":"Probe section","paragraphs":[{"text":"The probe paragraph states two atoms","atoms":["The first unit E probe atom","The second unit E probe atom"],"generality":[3,3],"confidence":0.8}]}],"relationships":[{"source_path":"sections/0/paragraphs/0/atoms/0","target_path":"sections/0/paragraphs/0/atoms/1","relationship":"supports"}]}'
R=$(tool ingest_document_inline "{\"extraction\":$DOC}")
echo "$R" | tail -c 400; echo
for _ in $(seq 1 30); do
  N=$(q "SELECT count(*) FROM claims WHERE 'doi:$DOI' = ANY(labels)")
  [ "${N:-0}" -ge 5 ] && break
  sleep 1
done
sleep 2
q "SELECT '   papers='||(SELECT count(*) FROM papers WHERE doi='$DOI')
        ||' doc_claims='||(SELECT count(*) FROM claims WHERE 'doi:$DOI' = ANY(labels))
        ||' asserts_edges='||(SELECT count(*) FROM edges e JOIN papers p ON p.id=e.source_id WHERE p.doi='$DOI' AND e.relationship='asserts')
        ||' atom_bbas='||(SELECT count(*) FROM mass_functions m JOIN claims c ON c.id=m.claim_id WHERE c.content LIKE 'The % unit E probe atom')
        ||' traces='||(SELECT count(*) FROM reasoning_traces t JOIN claims c ON c.trace_id=t.id WHERE 'doi:$DOI' = ANY(c.labels))
        ||' processed_by='||(SELECT count(*) FROM edges e JOIN papers p ON p.id=e.source_id WHERE p.doi='$DOI' AND e.relationship='processed_by')"

pb() { q "SELECT count(*) FROM edges e JOIN papers p ON p.id=e.source_id WHERE p.doi='$1' AND e.relationship='processed_by'"; }
settle() {  # $1 = doi: wait for the detached task to write processed_by, or give up
  for _ in $(seq 1 20); do [ "$(pb "$1")" -ge 1 ] && break; sleep 1; done; sleep 1
}

echo "--- re-ingest of the SAME document: must converge, not accumulate ---"
R=$(tool ingest_document_inline "{\"extraction\":$DOC}")
sleep 4
q "SELECT '   doc_claims='||(SELECT count(*) FROM claims WHERE 'doi:$DOI' = ANY(labels))
        ||' traces='||(SELECT count(*) FROM reasoning_traces t JOIN claims c ON c.trace_id=t.id WHERE 'doi:$DOI' = ANY(c.labels))
        ||' evidence='||(SELECT count(*) FROM evidence ev JOIN claims c ON c.id=ev.claim_id WHERE 'doi:$DOI' = ANY(c.labels))
        ||' processed_by='||(SELECT count(*) FROM edges e JOIN papers p ON p.id=e.source_id WHERE p.doi='$DOI' AND e.relationship='processed_by')"

echo "--- CONVERGED ATOM owned by ANOTHER group (the workflow ingest's operation atom) ---"
# Atoms are content-addressed: this document's first atom has the same text as
# an operation atom the ingest_workflow arm above wrote, owned by the
# workflow-ingest-system agent's group. The ingest resolves to that row and must
# still land the rest of the document.
DOI3="10.9999/unit-e-conv-$LABEL"
DOC3='{"source":{"title":"Unit E convergence paper","doi":"'"$DOI3"'","source_type":"Paper","authors":[]},"thesis":"Unit E convergence thesis","thesis_derivation":"TopDown","sections":[{"title":"Convergence section","paragraphs":[{"text":"The convergence paragraph","atoms":["Write the operation atom claims","A fresh unit E atom beside a converged one"],"generality":[3,3],"confidence":0.8}]}],"relationships":[]}'
q "SELECT '   converged atom before: owner='||COALESCE((SELECT owner_group_id::text FROM claims WHERE content='Write the operation atom claims'),'absent')"
R=$(tool ingest_document_inline "{\"extraction\":$DOC3}")
echo "$R" | tail -c 200; echo
settle "$DOI3"
q "SELECT '   processed_by='||(SELECT count(*) FROM edges e JOIN papers p ON p.id=e.source_id WHERE p.doi='$DOI3' AND e.relationship='processed_by')
        ||' doc_claims='||(SELECT count(*) FROM claims WHERE 'doi:$DOI3' = ANY(labels))
        ||' fresh_atom='||(SELECT count(*) FROM claims WHERE content='A fresh unit E atom beside a converged one')
        ||' asserts_to_converged='||(SELECT count(*) FROM edges e JOIN papers p ON p.id=e.source_id JOIN claims c ON c.id=e.target_id
                                      WHERE p.doi='$DOI3' AND e.relationship='asserts' AND c.content='Write the operation atom claims')"

echo
echo "=== E1: ingest_document_spine (synchronous phase 1 of the two-phase flow) ==="
DOI4="10.9999/unit-e-spine-$LABEL"
DOC4='{"source":{"title":"Unit E spine paper","doi":"'"$DOI4"'","source_type":"Paper","authors":[{"name":"Spine Author","affiliations":[],"roles":["author"]}]},"thesis":"Unit E spine thesis","thesis_derivation":"TopDown","sections":[{"title":"Spine section","paragraphs":[{"text":"The unit E spine paragraph","atoms":[],"generality":[],"confidence":0.8}]}],"relationships":[]}'
R=$(tool ingest_document_spine "{\"extraction\":$DOC4}")
echo "$R" | tail -c 300; echo
q "SELECT '   spine_claims='||(SELECT count(*) FROM claims WHERE 'doi:$DOI4' = ANY(labels))
        ||' processed_by='||(SELECT count(*) FROM edges e JOIN papers p ON p.id=e.source_id WHERE p.doi='$DOI4' AND e.relationship='processed_by')
        ||' authored='||(SELECT count(*) FROM edges e JOIN papers p ON p.id=e.target_id WHERE p.doi='$DOI4' AND e.relationship='authored')"

echo
echo "=== G8: a CHUNKED spine ingest (chapter 1, then 3, then 3 again) stamps each chunk once ==="
# Both processed_by writers used to dedup on (paper, agent, processed_by), so
# chapter 3's stamp was never written and check_already_ingested(':ch3') read
# false for an ingested chapter. Expect stamps=[..:ch1, ..:ch3], ch3=true,
# ch2=false, and 2 edges after the re-run.
DOI6="10.9999/unit-e-chunked-$LABEL"
for CH in 1 3 3; do
  DOC6='{"source":{"title":"Unit E chunked book ch'"$CH"'","doi":"'"$DOI6"'","source_type":"Textbook","authors":[],"metadata":{"chapter_index":'"$CH"'}},"thesis":"Unit E chunked thesis ch'"$CH"'","thesis_derivation":"TopDown","sections":[{"title":"Chunk section","paragraphs":[{"text":"The unit E chunk paragraph of chapter '"$CH"'","atoms":[],"generality":[],"confidence":0.8}]}],"relationships":[]}'
  tool ingest_document_spine "{\"extraction\":$DOC6}" | grep -oE '"isError":(true|false)' | head -1 | sed "s/^/   ch$CH /"
done
for PV in "" "hierarchical_extraction_v2:ch3" "hierarchical_extraction_v2:ch2"; do
  if [ -z "$PV" ]; then ARGS="{\"doi\":\"$DOI6\"}"; NAME=default; else ARGS="{\"doi\":\"$DOI6\",\"pipeline_version\":\"$PV\"}"; NAME="${PV##*:}"; fi
  R=$(tool check_already_ingested "$ARGS")
  echo "   check($NAME): $(echo "$R" | grep -oE 'already_ingested\\": (true|false)' | head -1) $(echo "$R" | grep -oE 'matched_pipeline_versions\\": \[[^]]*\]' | head -1)"
done
q "SELECT '   stamps='||COALESCE(string_agg(e.properties->>'pipeline', ',' ORDER BY e.properties->>'pipeline'),'none')
        ||' processed_by='||count(*)
   FROM edges e JOIN papers p ON p.id=e.source_id WHERE p.doi='$DOI6' AND e.relationship='processed_by'"

echo
echo "=== E1 PREFLIGHT: a detached ingest the author cannot write must be refused SYNCHRONOUSLY ==="
# ingest_document runs detached, so a refusal inside the task reaches no caller.
# With the server agent's memberships revoked, the synchronous preflight must
# return an error and write NOTHING — not even the papers row — instead of
# answering "queued" over a task that cannot write.
MA=$(q "SELECT agent_id FROM claims WHERE content='Unit E register probe parent' LIMIT 1")
if [ -n "$MA" ]; then
  DOI5="10.9999/unit-e-preflight-$LABEL"
  DOC5='{"source":{"title":"Unit E preflight paper","doi":"'"$DOI5"'","source_type":"Paper","authors":[]},"thesis":"Unit E preflight thesis","thesis_derivation":"TopDown","sections":[{"title":"Preflight section","paragraphs":[{"text":"The preflight paragraph","atoms":["The unit E preflight atom"],"generality":[3],"confidence":0.8}]}],"relationships":[]}'
  q "UPDATE group_memberships SET revoked_at = now() WHERE agent_id = '$MA' AND revoked_at IS NULL" >/dev/null
  R=$(tool ingest_document_inline "{\"extraction\":$DOC5}")
  echo "$R" | grep -oE '"isError":(true|false)|"message":"[^"]{0,200}' | head -1 | sed 's/^/   /'
  sleep 3
  q "SELECT '   papers='||(SELECT count(*) FROM papers WHERE doi='$DOI5')
          ||' doc_claims='||(SELECT count(*) FROM claims WHERE 'doi:$DOI5' = ANY(labels))
          ||' membership='||(SELECT 'live='||count(*) FILTER (WHERE revoked_at IS NULL)||' revoked='||count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM group_memberships WHERE agent_id='$MA')"
  q "UPDATE group_memberships SET revoked_at = NULL WHERE agent_id = '$MA'" >/dev/null
else
  echo "   SKIP: could not identify the server's own agent"
fi

echo
echo "=== E1 REVOKED: hard constraint #3 — a revoked ingest-system membership must NOT be revived ==="
# The executor authors every row as the workflow-ingest-system agent. Revoke
# that agent's membership(s) as the superuser, call store_workflow, and re-read
# revoked_at. PASS = the call refuses loudly, writes nothing, and the membership
# is STILL revoked. The first E1 revision revived it (live 0 -> 1) and committed.
# The agent is identified off a claim the ingest above wrote, never by
# display_name (not unique — see README trap 1).
SYS=$(q "SELECT agent_id FROM claims WHERE 'workflow_step' = ANY(labels) LIMIT 1")
if [ -z "$SYS" ]; then
  echo "   SKIP: no executor-authored claim to identify the system agent by"
else
  q "UPDATE group_memberships SET revoked_at = now() WHERE agent_id = '$SYS' AND revoked_at IS NULL" >/dev/null
  mstate() { q "SELECT 'live='||count(*) FILTER (WHERE revoked_at IS NULL)||' revoked='||count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM group_memberships WHERE agent_id='$SYS'"; }
  echo "   before: $(mstate)"
  CB=$(q "SELECT count(*) FROM claims WHERE agent_id='$SYS'"); WB=$(q "SELECT count(*) FROM workflows")
  R=$(tool store_workflow "{\"goal\":\"Unit E revoked ingest agent probe $LABEL\",\"steps\":[\"revoked probe step $LABEL\"]}")
  echo "$R" | tail -c 400; echo
  echo "   after:  $(mstate)   rows written: claims +$(( $(q "SELECT count(*) FROM claims WHERE agent_id='$SYS'") - CB )) workflows +$(( $(q "SELECT count(*) FROM workflows") - WB ))"
  # Restore, so the database is usable by the next run. This is the operator
  # action the refusal names.
  q "UPDATE group_memberships SET revoked_at = NULL WHERE agent_id = '$SYS'" >/dev/null

  echo "--- E1 READER: a LIVE read-only membership must not be silently promoted to admin ---"
  q "UPDATE group_memberships SET role = 'reader' WHERE agent_id = '$SYS'" >/dev/null
  rstate() { q "SELECT 'roles='||string_agg(role||CASE WHEN revoked_at IS NULL THEN '(live)' ELSE '(revoked)' END, ',') FROM group_memberships WHERE agent_id='$SYS'"; }
  echo "   before: $(rstate)"
  CB=$(q "SELECT count(*) FROM claims WHERE agent_id='$SYS'")
  R=$(tool store_workflow "{\"goal\":\"Unit E reader ingest agent probe $LABEL\",\"steps\":[\"reader probe step $LABEL\"]}")
  echo "$R" | tail -c 300; echo
  echo "   after:  $(rstate)   rows written: claims +$(( $(q "SELECT count(*) FROM claims WHERE agent_id='$SYS'") - CB ))"
  q "UPDATE group_memberships SET role = 'admin' WHERE agent_id = '$SYS'" >/dev/null
fi

echo
echo "=== REVIEW ARMS (Unit E revise round) ==="

echo
echo "=== PLAN ORDER: store_workflow 6 steps, report_workflow_outcome step_index 0..5 ==="
# The walk is ONE transaction, so every executes edge shares one created_at. A
# reader keyed on (created_at, c.id) attributes steps in UUID order. PASS =
# misattributed=0. The first Unit E revision measured 4 of 6 misattributed here,
# on both configs, with isError:false.
PO_STEPS='"alpha: gather the inputs","bravo: validate the inputs","charlie: run the transform","delta: check the output","echo: publish the output","foxtrot: record the run"'
R=$(tool store_workflow "{\"goal\":\"Unit E plan order probe $LABEL\",\"steps\":[$PO_STEPS]}")
PO_WF=$(uuid_of "$R" workflow_id)
if [ -n "$PO_WF" ]; then
  q "SELECT '   executes edges='||count(*)||' distinct created_at='||count(DISTINCT created_at) FROM edges WHERE source_id='$PO_WF' AND relationship='executes'"
  EX=""; i=0
  for s in "alpha: gather the inputs" "bravo: validate the inputs" "charlie: run the transform" "delta: check the output" "echo: publish the output" "foxtrot: record the run"; do
    EX="${EX:+$EX,}{\"step_index\":$i,\"planned\":\"$s\",\"actual\":\"done\",\"deviated\":false}"; i=$((i+1))
  done
  R=$(tool report_workflow_outcome "{\"workflow_id\":\"$PO_WF\",\"success\":true,\"outcome_details\":\"plan order probe\",\"execution_log\":[$EX]}")
  echo "   report: $(echo "$R" | grep -oE '"isError":(true|false)' | head -1)"
  q "SELECT '   behavioral_executions='||count(*)||' misattributed='||count(*) FILTER (WHERE c.content IS DISTINCT FROM b.tool_pattern[1])
       FROM behavioral_executions b LEFT JOIN claims c ON c.id=b.step_claim_id WHERE b.workflow_id='$PO_WF'"
else
  echo "   SKIP: store_workflow wrote no workflow: $(echo "$R" | tail -c 300)"
fi

echo
echo "=== STORE_WORKFLOW TWICE: a SECOND workflow on a database that already holds one ==="
# README trap 5. Every probe TRUNCATEs first, so "store_workflow succeeds" had
# only ever been measured for the FIRST workflow in a database. Its constant
# "Body" phase collides on uq_claims_content_hash_agent for every later one.
# PASS for this unit = the collision fails LOUDLY and ATOMICALLY (delta 0/0/0);
# the collision itself is open work (see the README).
CB=$(q "SELECT count(*) FROM claims"); WB=$(q "SELECT count(*) FROM workflows"); EB=$(q "SELECT count(*) FROM edges")
R=$(tool store_workflow "{\"goal\":\"Unit E second workflow probe $LABEL\",\"steps\":[\"second workflow step $LABEL\"]}")
echo "   $(echo "$R" | grep -oE '"isError":(true|false)|"message":"[^"]{0,160}|workflow_id[^,]{0,60}' | head -2 | tr '\n' ' ')"
echo "   delta: claims=$(( $(q "SELECT count(*) FROM claims") - CB )) workflows=$(( $(q "SELECT count(*) FROM workflows") - WB )) edges=$(( $(q "SELECT count(*) FROM edges") - EB ))"

echo
echo "=== TRANSACTIONAL EVENTS: claim.created timestamps of one ingest_workflow ==="
# Measures the disclosure on EventRepository::publish_or_log_conn: a walk's events
# share the transaction's START time.
q "SELECT '   claim.created events='||sum(n)||' in '||count(*)||' distinct created_at values; largest group sharing ONE created_at='||max(n)
     FROM (SELECT created_at, count(*) n FROM events WHERE event_type='claim.created' GROUP BY created_at) g"

echo
echo "=== HIDDEN AXIS FRAME: one unresolvable axis entry must not roll back the document's other BBAs ==="
# A frame named like the declared axis exists but is invisible to the ingesting
# agent: get_by_name -> None, create -> 23505. Before the savepoint fix that
# aborted the post-commit DS transaction and its COMMIT silently rolled back
# every BBA (review: binary_atom_bbas 2 -> 0). PASS = binary_atom_bbas=2 on both.
AX_G=$(q "INSERT INTO groups (display_name, did_key, public_key, kind) VALUES ('ue axis owner $LABEL', 'did:ue:axis:$LABEL:'||gen_random_uuid(), decode(repeat('ef',32),'hex'), 'team') RETURNING id" | head -1)
ax_doc() {  # $1 tag  $2 axis frame name
  local DOI="10.9999/unit-e-axis-$LABEL-$1"
  local D='{"source":{"title":"Unit E axis '"$1"'","doi":"'"$DOI"'","source_type":"Paper","authors":[]},"thesis":"Unit E axis thesis '"$1"'","thesis_derivation":"TopDown","sections":[{"title":"Binary","paragraphs":[{"text":"Binary paragraph '"$1"'","atoms":["Binary atom one of axis probe '"$1"'","Binary atom two of axis probe '"$1"'"],"generality":[3,3],"confidence":0.8}]},{"title":"Axis","paragraphs":[{"text":"Axis paragraph '"$1"'","atoms":["Axis atom of axis probe '"$1"'"],"generality":[3],"confidence":0.8,"axis":{"frame":"'"$2"'","hypotheses":["low","high"],"label":"high"}}]}],"relationships":[{"source_path":"sections/0/paragraphs/0/atoms/0","target_path":"sections/0/paragraphs/0/atoms/1","relationship":"supports"}]}'
  local RR; RR=$(tool ingest_document_inline "{\"extraction\":$D}")
  echo "   [$1] $(echo "$RR" | grep -oE '"isError":(true|false)' | head -1)"
  settle "$DOI"; sleep 2
  q "SELECT '   [$1] doc_claims='||(SELECT count(*) FROM claims WHERE 'doi:$DOI'=ANY(labels))
          ||' atom_bbas='||(SELECT count(*) FROM mass_functions m JOIN claims c ON c.id=m.claim_id WHERE c.content LIKE '% of axis probe $1')
          ||' binary_atom_bbas='||(SELECT count(*) FROM mass_functions m JOIN claims c ON c.id=m.claim_id WHERE c.content LIKE 'Binary atom % of axis probe $1')"
}
ax_doc ctl "ue_axis_fresh_$LABEL"
q "INSERT INTO frames (name, description, hypotheses, visibility, owner_group_id) VALUES ('ue_axis_hidden_$LABEL', 'hidden', ARRAY['low','high'], 'group', '$AX_G')" >/dev/null
ax_doc trg "ue_axis_hidden_$LABEL"

echo
echo "=== PERSONAL-REVOKED: server agent revoked in its PERSONAL group, live writer in a TEAM group ==="
# Hard constraint #3. Review measured personal:admin(revoked) -> (live) and +3/+4
# claims committed by ingest_document_inline. Three arms, each ASSERTED:
#   warm    the session that already resolved the agent;
#   fresh   a NEW MCP session of the same process. Batch F F1: the HTTP
#           transport builds a server per session, and before `SessionFactory`
#           each one re-ran `ensure_personal_group` (the reviving 077 body);
#   restart a NEW PROCESS, whose empty agent-id cell reaches the provisioning
#           call again. Only migration 105 (refuse, never revive) covers it.
# PASS for each = refused, personal still admin(revoked), +0 claims.
MA=$(q "SELECT agent_id FROM claims WHERE content='Unit E register probe parent' LIMIT 1")
new_session() {
  curl -s --unix-socket "$SOCK" "${H[@]}" -X POST http://localhost/mcp -D "$E2E/ueh.$LABEL.s2" -o /dev/null \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"unit-e-probe-2","version":"1"}}}'
  SID=$(grep -i '^mcp-session-id:' "$E2E/ueh.$LABEL.s2" | tr -d '\r' | cut -d' ' -f2)
  call '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
}
if [ -n "$MA" ]; then
  PG=$(q "SELECT id FROM groups WHERE did_key='did:epigraph:personal:$MA'")
  TG=$(q "INSERT INTO groups (display_name, did_key, public_key, kind) VALUES ('ue team $LABEL', 'did:ue:team:$LABEL:'||gen_random_uuid(), decode(repeat('ab',32),'hex'), 'team') RETURNING id" | head -1)
  q "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) VALUES ('$TG','$MA','\\x00',0,'writer')" >/dev/null
  pstate() { q "SELECT string_agg(CASE WHEN group_id='$PG' THEN 'personal' ELSE 'team' END||':'||role||CASE WHEN revoked_at IS NULL THEN '(live)' ELSE '(revoked)' END, ' ' ORDER BY group_id='$PG' DESC) FROM group_memberships WHERE agent_id='$MA' AND group_id IN ('$PG','$TG')"; }
  pr_doc() {  # $1 tag
    echo '{"source":{"title":"Unit E personal '"$1"'","doi":"10.9999/unit-e-personal-'"$LABEL-$1"'","source_type":"Paper","authors":[]},"thesis":"Unit E personal thesis '"$1"'","thesis_derivation":"TopDown","sections":[{"title":"S","paragraphs":[{"text":"Unit E personal paragraph '"$1"'","atoms":["Unit E personal atom '"$1"'"],"generality":[3],"confidence":0.8}]}],"relationships":[]}'
  }
  for arm in warm fresh restart; do
    q "UPDATE group_memberships SET revoked_at = now() WHERE agent_id='$MA' AND group_id='$PG' AND revoked_at IS NULL" >/dev/null
    if [ "$arm" = fresh ]; then
      new_session
    elif [ "$arm" = restart ]; then
      kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
      start_server
      new_session
    fi
    CB=$(q "SELECT count(*) FROM claims WHERE agent_id='$MA'")
    echo "   [$arm] before: $(pstate)"
    R=$(tool ingest_document_inline "{\"extraction\":$(pr_doc "$arm")}")
    ERR=$(echo "$R" | grep -oE '"isError":(true|false)|"code":-?[0-9]+' | head -1)
    echo "   [$arm] $(echo "$R" | grep -oE '"isError":(true|false)|"message":"[^"]{0,140}' | head -2 | tr '\n' ' ')"
    sleep 4
    AFTER=$(pstate); DC=$(( $(q "SELECT count(*) FROM claims WHERE agent_id='$MA'") - CB ))
    echo "   [$arm] after:  $AFTER   claims by agent +$DC"
    case "$AFTER" in
      *"personal:admin(revoked)"*) if [ "$DC" = 0 ] && [ -n "$ERR" ] && [ "$ERR" != '"isError":false' ]; then
                                     echo "   [$arm] PASS: refused, still revoked, +0"
                                   else echo "   [$arm] FAIL: not refused or rows written ($ERR, +$DC)"; fi ;;
      *) echo "   [$arm] FAIL: the personal membership was REVIVED" ;;
    esac
  done
  q "UPDATE group_memberships SET revoked_at = NULL WHERE agent_id='$MA' AND group_id='$PG'" >/dev/null
  q "DELETE FROM group_memberships WHERE agent_id='$MA' AND group_id='$TG'" >/dev/null
else
  echo "   SKIP: could not identify the server's own agent"
fi

echo
echo "=== RECALL (#493): recall must not revive a revoked principal's personal membership ==="
# The recall audit resolved its owner group by a blind read on the unstamped
# pool and then MINTED — the reviving 077 body — on every recall. PASS = the
# revoked membership is still revoked after a recall, and a recall by a LIVE
# member still answers.
if [ -n "$MA" ] && [ -n "$OPENAI_API_KEY" ]; then
  rstate() { q "SELECT 'live='||count(*) FILTER (WHERE revoked_at IS NULL)||' revoked='||count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM group_memberships WHERE agent_id='$MA' AND group_id='$PG'"; }
  q "UPDATE group_memberships SET revoked_at = now() WHERE agent_id='$MA' AND group_id='$PG' AND revoked_at IS NULL" >/dev/null
  echo "   [revoked] before: $(rstate)"
  R=$(tool recall '{"query":"Unit E register probe parent","limit":3}')
  echo "   [revoked] recall $(echo "$R" | grep -oE '"isError":(true|false)' | head -1)"
  sleep 3
  AFTER=$(rstate); echo "   [revoked] after:  $AFTER"
  [ "$AFTER" = "live=0 revoked=1" ] && echo "   [revoked] PASS: still revoked" || echo "   [revoked] FAIL: revived by recall"
  q "UPDATE group_memberships SET revoked_at = NULL WHERE agent_id='$MA' AND group_id='$PG'" >/dev/null
  R=$(tool recall '{"query":"Unit E register probe parent","limit":3}')
  OK=$(echo "$R" | grep -oE '"isError":(true|false)' | head -1)
  echo "   [live] recall $OK hits=$(echo "$R" | grep -o 'claim_id' | wc -l) membership $(rstate)"
  [ "$OK" = '"isError":false' ] && echo "   [live] PASS: recall still answers for a live member" || echo "   [live] FAIL"
else
  echo "   SKIP: needs the server's own agent and OPENAI_API_KEY (recall embeds its query)"
fi

echo
echo "=== WARN / refusal lines from the server log ==="
grep -iE "42501|row-level|scoped_write|refus|25P02|failed" "$E2E/ue.$LABEL.log" | grep -v OPERATED_BY | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-400 | tail -15
echo "(no lines above = nothing was refused server-side)"
