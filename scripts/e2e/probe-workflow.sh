#!/usr/bin/env bash
# Tool-level e2e probe for `deprecate_workflow` and `report_workflow_outcome`
# ON THEIR OWN TARGET POPULATION.
#
#   ./probe-workflow.sh <binary> <label> <a|b|b2a>
#
# # The three configurations, and why `b2a` is the one that answers the question
#
#   a     seed and measure on the clean migration series.
#   b     seed and measure on the prod-faithful series (A + the orphan policies).
#   b2a   SEED on B, then drop the orphan policies and MEASURE on A.
#
# `a` USED TO answer nothing about these two tools, and this was MEASURED, not
# assumed: on the clean series `store_workflow` was itself refused --
#
#   "workflow ingest: repository error: Query failed: error returned from
#    database: new row violates row-level security policy for table \"claims\""
#
# -- because `epigraph_ingest_executor` wrote on the unstamped pool as the
# system agent. So there was no workflow to deprecate and every downstream arm
# was vacuous by absence.
#
# THAT IS NO LONGER TRUE, and `a` is now the primary mode. The executor takes a
# connection the caller has stamped from the `workflow-ingest-system` agent's
# viewer, so `store_workflow` lands on a clean migration series. The refusal
# above is retained verbatim because it is what this mode is now the regression
# test FOR: running `a` against a binary from before that conversion reproduces
# it exactly, which is how the two binaries are told apart.
#
# `b2a` remains the R3 remediation itself: production's workflow claims were all
# written under B, and the remediation drops the orphan policies underneath them.
# That is the state in which `deprecate_workflow` and `report_workflow_outcome`
# must still work, and the state their conversion was supposed to reach.
#
# # Why this script exists and `probe-tools.sh` is not a substitute
#
# `probe-tools.sh` hangs every arm off a claim created by `submit_claim`, i.e. one
# AUTHORED BY THE MCP SERVER'S OWN AGENT and therefore owned by that agent's
# personal group. For a tool stamped from `server.agent_id()` that is the ONE case
# that cannot fail, so it measures the conversion on the only population the
# conversion trivially covers.
#
# Workflow claims are not that population. `store_workflow` and `ingest_workflow`
# both route through `epigraph_ingest_executor::execute_workflow_ingest_plan`,
# which resolves `get_or_create_system_agent` ("workflow-ingest-system") and passes
# THAT id to `create_with_id_if_absent` together with
# `default_decl_for_author_pool(pool, system_agent_id)`. So every workflow claim
# and every step claim is owned by the system agent's personal group, which the
# MCP process's own agent is not a member of.
#
# This probe therefore seeds through `store_workflow` and then addresses
# `deprecate_workflow` / `report_workflow_outcome` at the ids `store_workflow`
# returns, on the real non-bypassing `epigraph_app` role.
#
# # The trap this probe had to avoid
#
# `deprecate_workflow` passes ONE id to both `ClaimRepository::deprecate_claim`
# (a `claims` row) and `WorkflowRepository::set_truth_value` (a `workflows` row),
# and those two ids come from different derivations. If the id is not a claim id,
# `deprecate_claim` matches zero rows, NO 42501 is raised, and the tool reports
# success -- which is indistinguishable from "the write was allowed". The
# IDENTITY CHECK below is printed before any verdict for exactly that reason:
# read it first, because a `as_claim=0` line makes every refusal/success line
# underneath it meaningless.
#
# Same transport, role, database and advisory lock as the sibling scripts.
#
# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB (migrations,
#                policy replay, row counts).  e.g. postgres://u:p@host:5432/epigraph_e2e_test
#   E2E_APP_DSN  the least-privilege application DSN the server connects as.
#                MUST be a role with rolbypassrls=false, or every arm is vacuous.
# Optional:
#   OPENAI_API_KEY  the embedder is best-effort here; its absence does NOT make
#                   this probe vacuous (unlike probe-embed.sh), because the
#                   verdict is `claims.is_current` / refusal text, not `embedding`.
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
BIN="${1:?usage: probe-workflow.sh <binary> <label> <a|b|b2a>}"
LABEL="${2:?label}"
CFG="${3:?a|b|b2a}"
case "$CFG" in a) SEED=a; MEASURE=a;; b) SEED=b; MEASURE=b;; b2a) SEED=b; MEASURE=a;; *) echo "usage: <a|b|b2a>"; exit 2;; esac
E2E="$(cd "$(dirname "$0")" && pwd)"
SOCK="$E2E/wf.sock.$LABEL"
H=(-H Content-Type:application/json -H Accept:application/json,text/event-stream)
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"

q() { PGPASSWORD="$E2E_SU_PW" psql -h 127.0.0.1 -U "$E2E_SU_USER" -d "$E2E_DB" -tA -c "$1"; }

echo "### binary: $BIN"
LOCKFIFO="$E2E/.wlock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$E2E_SU_PW" psql -h 127.0.0.1 -U "$E2E_SU_USER" -d "$E2E_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"
release_lock() { exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO"; }
echo "### serialized on advisory lock 918273645"

echo "### seeding on config $SEED, measuring on config $MEASURE"
"$E2E/set-config.sh" "$SEED"
q "TRUNCATE claims, evidence, edges, reasoning_traces, mass_functions, claim_frames,
           recall_events, challenges, events, workflows, behavioral_executions CASCADE;" >/dev/null 2>&1

rm -f "$SOCK"
DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
  --agent-key "$E2E_AGENT_KEY" \
  --listen "unix:$SOCK" --allow-unauthenticated-http > "$E2E/wf.$LABEL.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; release_lock' EXIT
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 1; done
[ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -20 "$E2E/wf.$LABEL.log"; exit 1; }

call() { curl -s --unix-socket "$SOCK" "${H[@]}" -H "mcp-session-id: $SID" \
           -X POST http://localhost/mcp -d "$1" | grep '^data: {' | tail -1; }

curl -s --unix-socket "$SOCK" "${H[@]}" -X POST http://localhost/mcp -D "$E2E/wh.$LABEL" -o /dev/null \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"wf-probe","version":"1"}}}'
SID=$(grep -i '^mcp-session-id:' "$E2E/wh.$LABEL" | tr -d '\r' | cut -d' ' -f2)
call '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

echo "--- store_workflow (seeds an executor-authored workflow) ---"
SW=$(call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"store_workflow","arguments":{"goal":"Probe the workflow write path for executor authored claims","steps":["First step of the probe workflow","Second step of the probe workflow"]}}}')
echo "$SW" | tail -c 300
echo
WFID=$(echo "$SW" | grep -oE '"workflow_id\\": \\"[0-9a-f-]{36}' | head -1 | grep -oE '[0-9a-f-]{36}')
[ -n "${WFID:-}" ] || { echo "FAIL: no workflow_id; store_workflow said: $SW"; exit 1; }
echo "--- workflow_id: $WFID ---"

echo "=== IDENTITY CHECK (read this BEFORE any verdict below) ==="
# THE COLUMN IS `display_name`. `agents.name` and `groups.name` DO NOT EXIST --
# an earlier revision of this block asked for them, every statement here failed
# with `column a.name does not exist`, and because `q` runs psql WITHOUT
# ON_ERROR_STOP the errors printed and the probe carried on to report verdicts
# under an IDENTITY CHECK that had measured nothing. That is precisely the
# "a vacuous check that looks like a measurement" failure the README's trap list
# collects, in the one block the README tells the reader to consult FIRST.
q "SELECT 'as_claim='   ||(SELECT count(*) FROM claims    WHERE id='$WFID')
        ||' as_workflow='||(SELECT count(*) FROM workflows WHERE id='$WFID')
        ||' owner_group='||COALESCE((SELECT owner_group_id::text FROM claims WHERE id='$WFID'),'n/a')
        ||' author='     ||COALESCE((SELECT a.display_name FROM claims c JOIN agents a ON a.id=c.agent_id WHERE c.id='$WFID'),'n/a')"
echo "--- the thesis claim the workflow ingest wrote, which IS a claim ---"
q "SELECT '   thesis_claims='||count(*)
        ||' owner_groups='||COALESCE(string_agg(DISTINCT c.owner_group_id::text,','),'-')
        ||' authors='||COALESCE(string_agg(DISTINCT a.display_name,','),'-')
     FROM claims c JOIN agents a ON a.id=c.agent_id
     JOIN edges e ON e.target_id=c.id AND e.source_type='workflow' AND e.relationship='executes'
    WHERE e.source_id='$WFID'"
echo "--- the MCP server process's own agent, for contrast ---"
q "SELECT 'mcp_agent='||COALESCE((SELECT display_name FROM agents WHERE display_name='mcp-agent' LIMIT 1),'absent')
        ||' mcp_group='||COALESCE((SELECT g.id::text FROM groups g JOIN agents a ON g.display_name='personal:'||a.id::text
                                     WHERE a.display_name='mcp-agent' LIMIT 1),'n/a')"
echo "--- every claim this seed created, by author ---"
q "SELECT a.display_name||' x'||count(*) FROM claims c JOIN agents a ON a.id=c.agent_id GROUP BY a.display_name ORDER BY 1"

echo
echo "=== REACHABILITY: can any DISCOVERY tool hand deprecate_workflow a"
echo "=== system-agent-owned CLAIM id? (deprecate_workflow has no id fork, so"
echo "=== this is what decides whether its foreign-owner case is live.)"
for TOOL in find_workflow find_workflow_hierarchical; do
  echo "--- $TOOL ---"
  if [ "$TOOL" = find_workflow_hierarchical ]; then ARG='"query"'; else ARG='"goal"'; fi
  RES=$(call "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"$TOOL\",\"arguments\":{$ARG:\"Probe the workflow write path for executor authored claims\"}}}")
  echo "$RES" | tail -c 250
  echo
  IDS=$(echo "$RES" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | sort -u | tr '\n' ',' | sed 's/,$//')
  if [ -n "$IDS" ]; then
    q "SELECT '   returned id '||x||' -> in claims: '||
              (SELECT count(*) FROM claims WHERE id = x::uuid)||
              ' labels='||COALESCE((SELECT labels::text FROM claims WHERE id=x::uuid),'-')||
              ' owner='||COALESCE((SELECT owner_group_id::text FROM claims WHERE id=x::uuid),'-')||
              ' | in workflows: '||(SELECT count(*) FROM workflows WHERE id = x::uuid)
         FROM unnest(string_to_array('$IDS',',')) AS x"
  else
    echo "   (no uuids returned)"
  fi
done


# ── THE FLIP ────────────────────────────────────────────────────────────────
# Everything above is the SEED and ran on config $SEED. Everything below is the
# MEASUREMENT. On `b2a` the orphan policies are dropped right here, with the
# server process and its pooled connections untouched -- policies are evaluated
# per statement, so this is exactly the R3 remediation applied to a live server.
if [ "$SEED" != "$MEASURE" ]; then
  echo
  echo "### FLIPPING to config $MEASURE (the R3 remediation, applied mid-run)"
  "$E2E/set-config.sh" "$MEASURE"
fi

echo
echo "=== ARM 1: report_workflow_outcome (evidence INSERT + UPDATE claims) ==="
call "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"report_workflow_outcome\",\"arguments\":{\"workflow_id\":\"$WFID\",\"success\":true,\"quality\":0.9,\"outcome_details\":\"probe outcome\",\"execution_log\":[{\"step_index\":0,\"planned\":\"First step of the probe workflow\",\"actual\":\"First step of the probe workflow\",\"deviated\":false}]}}}" | tail -c 500
echo
q "SELECT 'evidence_on_workflow='||(SELECT count(*) FROM evidence WHERE claim_id='$WFID')
        ||' mass_functions='||(SELECT count(*) FROM mass_functions)
        ||' behavioral_executions='||(SELECT count(*) FROM behavioral_executions)"

echo
echo "=== ARM 2: deprecate_workflow (UPDATE claims, cascade on) ==="
call "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"deprecate_workflow\",\"arguments\":{\"workflow_id\":\"$WFID\",\"reason\":\"probe deprecation\",\"cascade\":true}}}" | tail -c 500
echo
echo "--- THE VERDICT: did the row actually flip? ---"
q "SELECT 'is_current='||COALESCE((SELECT is_current::text FROM claims WHERE id='$WFID'),'no-such-claim')
        ||' workflows.truth_value='||COALESCE((SELECT truth_value::text FROM workflows WHERE id='$WFID'),'n/a')
        ||' steps_still_current='||(SELECT count(*) FROM claims WHERE 'workflow_step'=ANY(labels) AND is_current)"

echo
echo "############################################################################"
echo "# ARMS 3-4: the LEGACY FLAT population -- the ONLY one that reaches the"
echo "# author-stamped code in either tool."
echo "#"
echo "# report_workflow_outcome probes \`workflows\` FIRST and, for a hierarchical"
echo "# id, returns through do_report_hierarchical_outcome_via_pool(&server.pool,..)"
echo "# -- so ARM 1 above never executed a single stamped statement. The stamped"
echo "# path is reached only for the legacy flat-workflow CLAIMS the tool's own"
echo "# comment counts at ~144. deprecate_workflow has no such fork: it calls"
echo "# deprecate_claim on whatever id it is handed, which is why ARM 2 above"
echo "# matched zero rows."
echo "#"
echo "# No tool creates that population any more, so it is seeded here as the"
echo "# superuser in the two ownership shapes that decide the question:"
echo "#   OWN     owned by the MCP process agent's personal group"
echo "#   FOREIGN owned by a group that agent is not a member of"
echo "# The stamp is from server.agent_id(), so OWN is the case it can serve and"
echo "# FOREIGN is the case it cannot."
echo "############################################################################"

# THE SERVER'S OWN AGENT, DERIVED FROM A WRITE IT MADE -- never by display_name.
# MEASURED TRAP: `agents.display_name = 'mcp-agent'` is NOT unique. Every run of
# this harness with a different --agent-key mints another row with that same
# display_name (14 of them on the shared e2e database at the time of writing), so
# `WHERE display_name='mcp-agent' LIMIT 1` picks an ARBITRARY previous run's
# agent. Seeding the "own-group" arm into that agent's group produced a 42501
# that looked exactly like the refusal this probe exists to detect -- a FALSE
# POSITIVE for the defect. `submit_claim` is authored by the server's own agent
# by construction, so reading `claims.agent_id` back off it is the only
# identification that cannot drift.
SUB=$(call '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"submit_claim","arguments":{"content":"Identify the MCP server process agent for the legacy flat arms","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.9,"novelty_threshold":0.0}}}')
SUBID=$(echo "$SUB" | grep -oE '"claim_id\\": \\"[0-9a-f-]{36}' | head -1 | grep -oE '[0-9a-f-]{36}')
MCP_AGENT=$(q "SELECT agent_id FROM claims WHERE id='${SUBID:-00000000-0000-0000-0000-000000000000}'" | head -1)
if [ -z "$MCP_AGENT" ]; then
  echo "SKIP arms 3-4: could not identify the server's own agent; submit_claim said: $SUB"
else
  echo "mcp-agent rows sharing that display_name: $(q "SELECT count(*) FROM agents WHERE display_name='mcp-agent'")"
  OWN_GROUP=$(q "SELECT public.epigraph_ensure_personal_group('$MCP_AGENT')")
  # THE SYSTEM AGENT, DERIVED FROM A WRITE IT MADE -- never by display_name, for
  # the same measured reason as `mcp-agent` above: `display_name` is not unique,
  # and picking an arbitrary row named `workflow-ingest-system` seeds the FOREIGN
  # arm into a group nothing authored, which yields a refusal that looks exactly
  # like the defect. The workflow ingest authors its claims as the real system
  # agent, so reading `claims.agent_id` back off one of them cannot drift.
  FOREIGN_AGENT=$(q "SELECT c.agent_id FROM claims c
                       JOIN edges e ON e.target_id=c.id AND e.source_type='workflow'
                                   AND e.relationship='executes'
                      WHERE e.source_id='$WFID' LIMIT 1")
  [ -n "$FOREIGN_AGENT" ] || FOREIGN_AGENT=$(q "SELECT id FROM agents WHERE display_name = 'workflow-ingest-system' LIMIT 1")
  FOREIGN_GROUP=$(q "SELECT public.epigraph_ensure_personal_group('$FOREIGN_AGENT')")
  echo "mcp-agent=$MCP_AGENT own_group=$OWN_GROUP"
  echo "workflow-ingest-system=$FOREIGN_AGENT foreign_group=$FOREIGN_GROUP"

  seed_flat() {   # $1 = label suffix, $2 = owner group, $3 = author agent
    q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current,
                           labels, properties, visibility, owner_group_id)
       VALUES (gen_random_uuid(), 'legacy flat workflow ($1)',
               decode(md5(random()::text)||md5(random()::text),'hex'), 0.5, '$3', true,
               ARRAY['workflow']::text[],
               '{\"goal\":\"legacy flat\",\"steps\":[\"s1\"],\"generation\":0,\"use_count\":0,\"success_count\":0}'::jsonb,
               'public', '$2')
       RETURNING id"
  }
  FLAT_OWN=$(seed_flat own "$OWN_GROUP" "$MCP_AGENT" | head -1)
  FLAT_FOREIGN=$(seed_flat foreign "$FOREIGN_GROUP" "$FOREIGN_AGENT" | head -1)
  echo "flat_own=$FLAT_OWN flat_foreign=$FLAT_FOREIGN"
  q "SELECT 'seeded as_claim_own='||(SELECT count(*) FROM claims WHERE id='$FLAT_OWN')
           ||' as_claim_foreign='||(SELECT count(*) FROM claims WHERE id='$FLAT_FOREIGN')"

  for WHICH in OWN FOREIGN; do
    if [ "$WHICH" = OWN ]; then FID=$FLAT_OWN; else FID=$FLAT_FOREIGN; fi
    echo
    echo "--- ARM 3/$WHICH: report_workflow_outcome on flat claim $FID ---"
    call "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"report_workflow_outcome\",\"arguments\":{\"workflow_id\":\"$FID\",\"success\":true,\"quality\":0.9,\"outcome_details\":\"probe\",\"execution_log\":[{\"step_index\":0,\"planned\":\"s1\",\"actual\":\"s1\",\"deviated\":false}]}}}" | tail -c 400
    echo
    q "SELECT '   evidence_rows='||(SELECT count(*) FROM evidence WHERE claim_id='$FID')"
    echo "--- ARM 4/$WHICH: deprecate_workflow on flat claim $FID ---"
    call "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"deprecate_workflow\",\"arguments\":{\"workflow_id\":\"$FID\",\"reason\":\"probe\",\"cascade\":false}}}" | tail -c 400
    echo
    q "SELECT '   is_current='||(SELECT is_current::text FROM claims WHERE id='$FID')"
  done
fi

echo
echo "=== WARN / refusal lines from the server log ==="
grep -iE "42501|row-level|scoped_write|refus|25P02" "$E2E/wf.$LABEL.log" | tail -12
echo "(no lines above = nothing was refused server-side)"
