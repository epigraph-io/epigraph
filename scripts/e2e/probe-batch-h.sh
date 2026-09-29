#!/usr/bin/env bash
# Batch H acceptance probe: the write tools that the other probes only ever
# reached with PUBLIC claims, measured on the real binary as the real
# least-privilege role, on GROUP-PRIVATE rows in both ownership shapes.
#
#   ./probe-batch-h.sh <epigraph-mcp binary> <label> <a|b> [arm ...]
#
# Arms (default: all):
#   patch_claim   patch_claim on own-public / own-private / foreign-private /
#                 foreign-public claims
#   edges         link_hierarchical, link_alternative, link_epistemic (with a
#                 belief-bearing source), patch_edge, delete_edge on
#                 own-private and foreign-private endpoints
#   resolve       resolve_backlog_item on the server agent's own backlog items,
#                 with a public, an own-private and a foreign-private basis, and
#                 an injected mid-call refusal of the justifies edge
#   submit_ds     submit_claim's DS wiring commits with the claim
#   maintenance   recompute_beliefs, sweep_semantic_duplicates and
#                 backfill_embeddings under four server configurations:
#                 MAINTENANCE_DATABASE_URL unset, set to the app login, set
#                 to E2E_MAINT_DSN (a role that satisfies epigraph_bypass()),
#                 and unset with the APPLICATION DSN itself bypass-capable
#                 (the fallback, which must never enable them)
#   supersede     supersede_claim on own-public / own-private / foreign-private /
#                 foreign-public claims (fresh rows, so no other arm sees them)
#   theme         theme_cluster (wipe_first=true) over public claims the server
#                 agent owns, with a pre-existing theme in place: the run must
#                 commit whole or leave the previous themes exactly as they were
#   maint_auth    the same tools over AUTHENTICATED HTTP (--jwt-secret, a
#                 random per-run secret that is never written to disk): a
#                 claims:write-only bearer with no membership must be refused
#                 before the tool body runs; a claims:admin bearer is admitted
#   caller_auth   batch H-b over AUTHENTICATED HTTP, with a caller that is NOT
#                 the server's signer: submit_claim is authored, owned and
#                 signed as D1 says (verify_claim valid), the caller's own
#                 patch_claim / update_labels land, a foreign claim is refused;
#                 a claims:admin bearer whose client record grants it relabels
#                 and patches a foreign claim through the AUDITED ADMIN PATH
#                 (migration 111: admin recorded, security_events row); an
#                 admin bearer with no such grant is refused, nothing written
#   op_http       #503's operator arm over AUTHENTICATED HTTP: the operator's
#                 claims:write bearer patches, relabels and resolves its linked
#                 agent's claims (owned by the operator's group) on the APP DSN
#   review_http   the batch H-b review's authority attacks over AUTHENTICATED
#                 HTTP: the H3 lineage takeover (a parentless generation+1),
#                 the workflow admin arm with and without a client grant, a
#                 teammate's update_labels, a forged perspective owner / event
#                 actor, a stranger's patch_edge, set_source_reliability over
#                 nothing; every attack must fail and write nothing
#   unauth_listener  the --allow-unauthenticated-http shape (injected
#                 claims:admin, nil client): foreign update_labels (free and
#                 resolved), resolve_backlog_item and add_step; D2 refuses all
#   cascade       supersede_claim whose downstream includes a FOREIGN public
#                 claim: it must keep its edge BBA and belief (and be reported)
#                 on A, and be repaired on B
#
# WHY THIS PROBE EXISTS. Every other arm in this directory seeds its claims
# through submit_claim, and submit_claim writes PUBLIC claims. An edge between
# two public claims is made world-owned by 070's BEFORE trigger and admitted by
# edges_tenancy's static arm with NO stamp at all, so on those rows a stamped
# write and an unstamped one are indistinguishable. The discriminating rows are
# group-private, and there are two shapes of them:
#   OWN      visibility='group', owned by the server agent's personal group. A
#            write stamped from the server agent must SUCCEED on config A.
#   FOREIGN  visibility='group', owned by a team group the server agent is not
#            in. It must FAIL LOUDLY AND ATOMICALLY on config A: an error, and
#            zero rows changed. On config B the orphan policies may admit it;
#            that is what R3 removes.
# Each line prints the tool's verdict AND the rows the database holds after it,
# because a success-shaped response over zero rows and an error over
# half-written rows are both failures that only the rows can reveal.
#
# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB.
#   E2E_APP_DSN  the least-privilege application DSN the server connects as.
#                MUST be a role with rolbypassrls=false, or every arm is vacuous.
# Optional:
#   E2E_MAINT_DSN   the maintenance DSN for the `maintenance` arm's third
#                   configuration. Defaults to E2E_SU_DSN (a superuser satisfies
#                   epigraph_bypass()). Must be on the test cluster.
#   OPENAI_API_KEY  the `maintenance` arm's backfill case REFUSES to report a
#                   verdict without it (trap 4 in README.md).
#   E2E_AGENT_KEY   32-byte hex Ed25519 seed for the server's own agent. Defaults
#                   to a deliberately public throwaway seed; never a real key.
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
E2E_MAINT_DSN="${E2E_MAINT_DSN:-$E2E_SU_DSN}"
# Refuse a DSN on the production port (or with no port/host) before anything
# runs; sets E2E_SU_PORT / E2E_SU_HOST, which every psql call below passes.
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
e2e_guard_dsn E2E_MAINT_DSN
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
E2E_AGENT_KEY="${E2E_AGENT_KEY:-000000000000000000000000000000000000000000000000000000000e2e5eed}"
# -----------------------------------------------------------------------------
set -uo pipefail
BIN="${1:?usage: probe-batch-h.sh <binary> <label> <a|b> [arm ...]}"
LABEL="${2:?label}"
CFG="${3:?a|b}"
shift 3
ARMS="${*:-patch_claim edges resolve submit_ds supersede theme maintenance maint_auth caller_auth op_http review_http unauth_listener cascade}"
command -v jq >/dev/null || { echo "probe-batch-h.sh needs jq to read tool responses" >&2; exit 2; }
E2E="$(cd "$(dirname "$0")" && pwd)"
SOCK="$E2E/bh.sock.$LABEL"
H=(-H Content-Type:application/json -H Accept:application/json,text/event-stream)
# Set by the maint_auth arm only: the bearer every call carries, and the JWT
# secret the server is started with. Both live in this process's memory only.
BEARER=""
JWT_SECRET=""
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"

q() { PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -X -tA -c "$1"; }
want() { case " $ARMS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

echo "### binary: $BIN"
echo "### arms: $ARMS"
# Serialized for the same reason as every other script here: TRUNCATE + count.
LOCKFIFO="$E2E/.bhlock.$LABEL"
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

PID=""
# $1 = maintenance mode: none | app | maint | fallback_bypass | auth
start_server() {
  local mode="${1:-none}"
  rm -f "$SOCK"
  case "$mode" in
    # MAINTENANCE_DATABASE_URL unset and the application DSN is itself able to
    # bypass RLS: the documented fallback must NOT attach it.
    fallback_bypass) env -u MAINTENANCE_DATABASE_URL DATABASE_URL="$E2E_MAINT_DSN" RUST_LOG=warn "$BIN" \
             --agent-key "$E2E_AGENT_KEY" --listen "unix:$SOCK" --allow-unauthenticated-http \
             >> "$E2E/bh.$LABEL.log" 2>&1 & ;;
    # Authenticated HTTP with a configured, bypass-capable maintenance DSN.
    auth)  EPIGRAPH_JWT_SECRET="$JWT_SECRET" MAINTENANCE_DATABASE_URL="$E2E_MAINT_DSN" DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
             --agent-key "$E2E_AGENT_KEY" --listen "unix:$SOCK" \
             >> "$E2E/bh.$LABEL.log" 2>&1 & ;;
    none)  env -u MAINTENANCE_DATABASE_URL DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
             --agent-key "$E2E_AGENT_KEY" --listen "unix:$SOCK" --allow-unauthenticated-http \
             >> "$E2E/bh.$LABEL.log" 2>&1 & ;;
    app)   MAINTENANCE_DATABASE_URL="$E2E_APP_DSN" DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
             --agent-key "$E2E_AGENT_KEY" --listen "unix:$SOCK" --allow-unauthenticated-http \
             >> "$E2E/bh.$LABEL.log" 2>&1 & ;;
    maint) MAINTENANCE_DATABASE_URL="$E2E_MAINT_DSN" DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
             --agent-key "$E2E_AGENT_KEY" --listen "unix:$SOCK" --allow-unauthenticated-http \
             >> "$E2E/bh.$LABEL.log" 2>&1 & ;;
  esac
  PID=$!
  for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 1; done
  [ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -20 "$E2E/bh.$LABEL.log"; exit 1; }
  curl -s --unix-socket "$SOCK" "${H[@]}" ${BEARER:+-H "Authorization: Bearer $BEARER"} -X POST http://localhost/mcp -D "$E2E/bhh.$LABEL" -o /dev/null \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"batch-h-probe","version":"1"}}}'
  SID=$(grep -i '^mcp-session-id:' "$E2E/bhh.$LABEL" | tr -d '\r' | cut -d' ' -f2)
  call '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
}
stop_server() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; }
: > "$E2E/bh.$LABEL.log"
trap 'stop_server; release_lock' EXIT

call() { curl -s --unix-socket "$SOCK" "${H[@]}" ${BEARER:+-H "Authorization: Bearer $BEARER"} -H "mcp-session-id: $SID" \
           -X POST http://localhost/mcp -d "$1" | grep '^data: {' | tail -1 | sed 's/^data: //'; }
tool() {  # $1 = tool name, $2 = JSON arguments
  call "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"
}
# One-line verdict: OK, or ERR/TOOLERR with the first 170 chars of the message.
verdict() {
  printf '%s' "$1" | jq -r '
    if .error then "ERR: " + (.error.message // "" | .[0:170])
    elif .result.isError then "TOOLERR: " + ((.result.content[0].text // "") | .[0:170])
    else "OK" end' 2>/dev/null || echo "UNPARSEABLE: ${1:0:120}"
}
# A field out of a successful tool response's JSON text.
field() { printf '%s' "$1" | jq -r ".result.content[0].text | fromjson | .$2 | if . == null then empty else tostring end" 2>/dev/null; }

start_server none

# ── Fixtures ────────────────────────────────────────────────────────────────
# The server agent's id and personal group are read back off a real
# submit_claim (README trap 1: never identify the agent by display name).
R=$(tool submit_claim '{"content":"Batch H own public anchor","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"novelty_threshold":0.0}')
C_OWN_PUB=$(field "$R" claim_id)
MA=$(q "SELECT agent_id FROM claims WHERE id='$C_OWN_PUB'")
OG=$(q "SELECT owner_group_id FROM claims WHERE id='$C_OWN_PUB'")
FA=$(q "INSERT INTO agents (public_key, display_name) VALUES (decode(md5(random()::text)||md5(random()::text),'hex'), 'batch-h foreign agent $LABEL') RETURNING id" | head -1)
FG=$(q "INSERT INTO groups (display_name, did_key, public_key, kind) VALUES ('batch-h foreign team $LABEL', 'did:bh:team:$LABEL:'||gen_random_uuid(), decode(repeat('cd',32),'hex'), 'team') RETURNING id" | head -1)
q "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) VALUES ('$FG','$FA','\\x00',0,'admin')" >/dev/null
echo "### server agent=$MA own group=$OG | foreign agent=$FA foreign group=$FG"
[ -n "$MA" ] && [ -n "$OG" ] && [ -n "$FA" ] && [ -n "$FG" ] || { echo "FAIL: fixtures did not seed"; exit 1; }

# seed <content> <visibility> <owner_group> <agent> [labels-array-literal]
seed() {
  q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id)
     VALUES (gen_random_uuid(), '$1', decode(md5(random()::text)||md5(random()::text),'hex'), 0.6,
             '$4', ${5:-ARRAY['claim']::text[]}, '$2', '$3') RETURNING id" | head -1
}
C_OWN_PRIV1=$(seed "Batch H own private one $LABEL" group "$OG" "$MA")
C_OWN_PRIV2=$(seed "Batch H own private two $LABEL" group "$OG" "$MA")
C_FOR_PRIV1=$(seed "Batch H foreign private one $LABEL" group "$FG" "$FA")
C_FOR_PRIV2=$(seed "Batch H foreign private two $LABEL" group "$FG" "$FA")
C_FOR_PUB=$(seed "Batch H foreign public $LABEL" public "$FG" "$FA")
echo "### own_priv=$C_OWN_PRIV1,$C_OWN_PRIV2 foreign_priv=$C_FOR_PRIV1,$C_FOR_PRIV2 foreign_pub=$C_FOR_PUB"

# ── patch_claim ─────────────────────────────────────────────────────────────
if want patch_claim; then
  echo
  echo "=== patch_claim: properties merge {\"bh\":1} ==="
  echo "    expect A: own_pub OK, own_priv OK, foreign_priv ERR (not found), foreign_pub ERR; patched only where OK"
  for pair in "own_pub:$C_OWN_PUB" "own_priv:$C_OWN_PRIV1" "foreign_priv:$C_FOR_PRIV1" "foreign_pub:$C_FOR_PUB"; do
    name="${pair%%:*}"; id="${pair#*:}"
    R=$(tool patch_claim "{\"claim_id\":\"$id\",\"properties\":{\"bh\":1},\"add_labels\":[\"bh-patched\"]}")
    echo "   $name: $(verdict "$R") | patched=$(q "SELECT count(*) FROM claims WHERE id='$id' AND properties ? 'bh'") labelled=$(q "SELECT count(*) FROM claims WHERE id='$id' AND 'bh-patched'=ANY(labels)")"
  done
fi

# ── edges ───────────────────────────────────────────────────────────────────
if want edges; then
  echo
  echo "=== link_hierarchical (decomposes_to) ==="
  echo "    expect A: own_priv->own_priv OK (group-owned edge), own_priv->foreign_priv ERR (not found), foreign_priv->own_pub ERR; edges only where OK"
  for pair in "own_priv->own_priv:$C_OWN_PRIV1:$C_OWN_PRIV2" "own_priv->foreign_priv:$C_OWN_PRIV1:$C_FOR_PRIV1" "foreign_priv->own_pub:$C_FOR_PRIV1:$C_OWN_PUB" "foreign_pub->own_priv:$C_FOR_PUB:$C_OWN_PRIV2"; do
    name="${pair%%:*}"; rest="${pair#*:}"; s="${rest%%:*}"; t="${rest#*:}"
    R=$(tool link_hierarchical "{\"source_claim_id\":\"$s\",\"target_claim_id\":\"$t\",\"relationship\":\"decomposes_to\"}")
    echo "   $name: $(verdict "$R") | edges=$(q "SELECT count(*)||' owner='||COALESCE(string_agg(owner_group_id::text||'/'||visibility||COALESCE('/co:'||co_owner_group_id::text,''),','),'-') FROM edges WHERE source_id='$s' AND target_id='$t' AND relationship='decomposes_to'")"
  done

  echo
  echo "=== link_alternative ==="
  echo "    expect A: own_priv<->own_priv OK, own_priv<->foreign_priv ERR"
  for pair in "own_priv<->own_priv:$C_OWN_PRIV1:$C_OWN_PRIV2" "own_priv<->foreign_priv:$C_OWN_PRIV2:$C_FOR_PRIV2"; do
    name="${pair%%:*}"; rest="${pair#*:}"; a="${rest%%:*}"; b="${rest#*:}"
    R=$(tool link_alternative "{\"claim_a\":\"$a\",\"claim_b\":\"$b\",\"rationale\":\"probe\"}")
    echo "   $name: $(verdict "$R") | alternative_of=$(q "SELECT count(*) FROM edges WHERE relationship='alternative_of' AND ((source_id='$a' AND target_id='$b') OR (source_id='$b' AND target_id='$a'))")"
  done

  echo
  echo "=== link_epistemic (supports), belief-bearing OWN-PRIVATE endpoints ==="
  echo "    expect A: OK with belief_wired=true and a new target BBA; foreign target ERR with no edge"
  R1=$(tool submit_claim '{"content":"Batch H epistemic source","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.8,"novelty_threshold":0.0}')
  R2=$(tool submit_claim '{"content":"Batch H epistemic target","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.6,"novelty_threshold":0.0}')
  ES=$(field "$R1" claim_id); ET=$(field "$R2" claim_id)
  # Privatize both into the server agent's own group (they already carry its
  # owner_group_id and their BBAs). The propagation trigger carries the
  # visibility onto their derived rows.
  q "UPDATE claims SET visibility='group' WHERE id IN ('$ES','$ET')" >/dev/null
  MF_BEFORE=$(q "SELECT count(*) FROM mass_functions WHERE claim_id='$ET'")
  R=$(tool link_epistemic "{\"source_claim_id\":\"$ES\",\"target_claim_id\":\"$ET\",\"relationship\":\"supports\"}")
  echo "   own_priv->own_priv: $(verdict "$R") belief_wired=$(field "$R" belief_wired) | supports_edges=$(q "SELECT count(*) FROM edges WHERE source_id='$ES' AND target_id='$ET' AND relationship='supports'") target_bbas $MF_BEFORE->$(q "SELECT count(*) FROM mass_functions WHERE claim_id='$ET'") edge_added_events=$(q "SELECT count(*) FROM events WHERE event_type='edge.added' AND payload->>'source_id'='$ES'")"
  R=$(tool link_epistemic "{\"source_claim_id\":\"$ES\",\"target_claim_id\":\"$C_FOR_PRIV2\",\"relationship\":\"refutes\"}")
  echo "   own_priv->foreign_priv: $(verdict "$R") | refutes_edges=$(q "SELECT count(*) FROM edges WHERE source_id='$ES' AND target_id='$C_FOR_PRIV2'") target_bbas=$(q "SELECT count(*) FROM mass_functions WHERE claim_id='$C_FOR_PRIV2'")"
  R=$(tool link_epistemic "{\"source_claim_id\":\"$ES\",\"target_claim_id\":\"$C_FOR_PUB\",\"relationship\":\"contradicts\"}")
  echo "   own_priv->foreign_pub (symmetric): $(verdict "$R") belief_wired=$(field "$R" belief_wired) | contradicts_edges=$(q "SELECT count(*)||' owner='||COALESCE(string_agg(owner_group_id::text||'/'||visibility,','),'-') FROM edges WHERE relationship='contradicts' AND source_id='$ES'") target_bbas=$(q "SELECT count(*) FROM mass_functions WHERE claim_id='$C_FOR_PUB'")"

  echo
  echo "=== patch_edge / delete_edge on an OWN-GROUP edge and a FOREIGN-GROUP edge (seeded by SU) ==="
  echo "    expect A: own edge patched=1 then in_force=0; foreign edge ERR (not found) and untouched"
  E_OWN=$(q "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ('$C_OWN_PRIV1','claim','$C_OWN_PRIV2','claim','bh_probe','{}'::jsonb) RETURNING id" | head -1)
  E_FOR=$(q "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ('$C_FOR_PRIV1','claim','$C_FOR_PRIV2','claim','bh_probe','{}'::jsonb) RETURNING id" | head -1)
  echo "   seeded: own=$E_OWN ($(q "SELECT owner_group_id||'/'||visibility FROM edges WHERE id='$E_OWN'")) foreign=$E_FOR ($(q "SELECT owner_group_id||'/'||visibility FROM edges WHERE id='$E_FOR'"))"
  for pair in "own:$E_OWN" "foreign:$E_FOR"; do
    name="${pair%%:*}"; id="${pair#*:}"
    R=$(tool patch_edge "{\"edge_id\":\"$id\",\"properties\":{\"bh\":1}}")
    P=$(verdict "$R")
    R=$(tool delete_edge "{\"edge_id\":\"$id\"}")
    D=$(verdict "$R")
    echo "   $name: patch_edge $P | delete_edge $D | patched=$(q "SELECT count(*) FROM edges WHERE id='$id' AND properties ? 'bh'") in_force=$(q "SELECT count(*) FROM edges WHERE id='$id' AND valid_to IS NULL") events=$(q "SELECT count(*) FROM events WHERE payload->>'edge_id'='$id'")"
  done
fi

# ── resolve_backlog_item ────────────────────────────────────────────────────
if want resolve; then
  echo
  echo "=== resolve_backlog_item ==="
  echo "    expect A: own item + public basis OK; own item + own-private basis OK; foreign-private basis ERR (not visible);"
  echo "              every ERR leaves resolutions=0 justifies=0 and the item unlabelled"
  RB=$(tool submit_claim '{"content":"Batch H backlog item","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"labels":["backlog"],"novelty_threshold":0.0}')
  ITEM=$(field "$RB" claim_id)
  RP=$(tool submit_claim '{"content":"Batch H public basis","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"novelty_threshold":0.0}')
  BPUB=$(field "$RP" claim_id)
  rb_rows() {  # $1 = item id
    echo "resolutions=$(q "SELECT count(*) FROM claims WHERE content LIKE 'Resolves $1:%'") justifies=$(q "SELECT count(*) FROM edges e JOIN claims c ON c.id=e.target_id WHERE e.relationship='justifies' AND c.content LIKE 'Resolves $1:%'") item_resolved=$(q "SELECT count(*) FROM claims WHERE id='$1' AND 'resolved'=ANY(labels)") justifies_owner=$(q "SELECT COALESCE(string_agg(DISTINCT e.owner_group_id::text||'/'||e.visibility,','),'-') FROM edges e JOIN claims c ON c.id=e.target_id WHERE e.relationship='justifies' AND c.content LIKE 'Resolves $1:%'")"
  }
  R=$(tool resolve_backlog_item "{\"original_id\":\"$ITEM\",\"resolution_content\":\"closed with a public basis\",\"basis_claim_ids\":[\"$BPUB\"]}")
  echo "   own item, public basis: $(verdict "$R") | $(rb_rows "$ITEM")"
  RB2=$(tool submit_claim '{"content":"Batch H backlog item two","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"labels":["backlog"],"novelty_threshold":0.0}')
  ITEM2=$(field "$RB2" claim_id)
  R=$(tool resolve_backlog_item "{\"original_id\":\"$ITEM2\",\"resolution_content\":\"closed with a private basis\",\"basis_claim_ids\":[\"$C_OWN_PRIV1\"]}")
  echo "   own item, own-private basis: $(verdict "$R") | $(rb_rows "$ITEM2")"
  RB3=$(tool submit_claim '{"content":"Batch H backlog item three","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"labels":["backlog"],"novelty_threshold":0.0}')
  ITEM3=$(field "$RB3" claim_id)
  R=$(tool resolve_backlog_item "{\"original_id\":\"$ITEM3\",\"resolution_content\":\"closed with a foreign basis\",\"basis_claim_ids\":[\"$C_FOR_PRIV1\"]}")
  echo "   own item, foreign-private basis: $(verdict "$R") | $(rb_rows "$ITEM3")"
  # The mid-call refusal: a basis the caller CAN read but whose justifies edge
  # the database refuses. A CHECK that fails every 'justifies' edge, added for
  # this one call, makes the edge INSERT fail after the resolution claim was
  # written. The call must then leave NOTHING: no resolution claim, no label.
  RB4=$(tool submit_claim '{"content":"Batch H backlog item four","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"labels":["backlog"],"novelty_threshold":0.0}')
  ITEM4=$(field "$RB4" claim_id)
  q "ALTER TABLE edges ADD CONSTRAINT bh_probe_no_justifies CHECK (relationship <> 'justifies') NOT VALID" >/dev/null
  R=$(tool resolve_backlog_item "{\"original_id\":\"$ITEM4\",\"resolution_content\":\"closed while justifies edges are refused\",\"basis_claim_ids\":[\"$BPUB\"]}")
  q "ALTER TABLE edges DROP CONSTRAINT bh_probe_no_justifies" >/dev/null
  echo "   injected edge refusal: $(verdict "$R") | $(rb_rows "$ITEM4")"
fi

# ── submit_claim DS wiring ─────────────────────────────────────────────────
if want submit_ds; then
  echo
  echo "=== submit_claim: DS wiring commits with the claim ==="
  echo "    expect: OK with a belief; claims=1 traces=1 evidence=1 bbas=1 claim_frames=1"
  R=$(tool submit_claim '{"content":"Batch H DS wiring probe","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.8,"novelty_threshold":0.0}')
  C=$(field "$R" claim_id)
  echo "   fresh: $(verdict "$R") belief=$(field "$R" belief) | claims=$(q "SELECT count(*) FROM claims WHERE content='Batch H DS wiring probe'") traces=$(q "SELECT count(*) FROM reasoning_traces rt JOIN claims c ON c.trace_id=rt.id WHERE c.id='${C:-00000000-0000-0000-0000-000000000000}'") evidence=$(q "SELECT count(*) FROM evidence WHERE claim_id='${C:-00000000-0000-0000-0000-000000000000}'") bbas=$(q "SELECT count(*) FROM mass_functions WHERE claim_id='${C:-00000000-0000-0000-0000-000000000000}'") claim_frames=$(q "SELECT count(*) FROM claim_frames WHERE claim_id='${C:-00000000-0000-0000-0000-000000000000}'") cached_belief=$(q "SELECT COALESCE(belief::text,'NULL') FROM claims WHERE id='${C:-00000000-0000-0000-0000-000000000000}'")"
  # The injected DS refusal: a CHECK that fails every mass_functions row makes
  # the wiring fail after the claim, trace and evidence were written. The call
  # must then fail loudly and leave nothing (the old shape committed the claim
  # and reported success with belief=null).
  q "ALTER TABLE mass_functions ADD CONSTRAINT bh_probe_no_bba CHECK (false) NOT VALID" >/dev/null
  R=$(tool submit_claim '{"content":"Batch H DS refusal probe","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.8,"novelty_threshold":0.0}')
  RM=$(tool memorize '{"content":"Batch H memorize DS refusal probe","tags":["bh-memo"]}')
  q "ALTER TABLE mass_functions DROP CONSTRAINT bh_probe_no_bba" >/dev/null
  echo "   injected BBA refusal, submit_claim: $(verdict "$R") belief=$(field "$R" belief) | claims=$(q "SELECT count(*) FROM claims WHERE content='Batch H DS refusal probe'") evidence=$(q "SELECT count(*) FROM evidence e JOIN claims c ON c.id=e.claim_id WHERE c.content='Batch H DS refusal probe'")"
  echo "   injected BBA refusal, memorize:     $(verdict "$RM") belief=$(field "$RM" belief) | claims=$(q "SELECT count(*) FROM claims WHERE content='Batch H memorize DS refusal probe'") evidence=$(q "SELECT count(*) FROM evidence e JOIN claims c ON c.id=e.claim_id WHERE c.content='Batch H memorize DS refusal probe'")"
  R=$(tool memorize '{"content":"Batch H memorize DS wiring probe","tags":["bh-memo"]}')
  C=$(field "$R" claim_id)
  echo "   memorize fresh: $(verdict "$R") belief=$(field "$R" belief) | claims=$(q "SELECT count(*) FROM claims WHERE content='Batch H memorize DS wiring probe'") bbas=$(q "SELECT count(*) FROM mass_functions WHERE claim_id='${C:-00000000-0000-0000-0000-000000000000}'")"
fi

# ── supersede_claim ────────────────────────────────────────────────────────
if want supersede; then
  echo
  echo "=== supersede_claim ==="
  echo "    expect A: own_pub OK, own_priv OK, foreign_priv ERR (not found), foreign_pub ERR; retired only where OK"
  S_OWN_PUB=$(seed "Batch H supersede own public $LABEL" public "$OG" "$MA")
  S_OWN_PRIV=$(seed "Batch H supersede own private $LABEL" group "$OG" "$MA")
  S_FOR_PRIV=$(seed "Batch H supersede foreign private $LABEL" group "$FG" "$FA")
  S_FOR_PUB=$(seed "Batch H supersede foreign public $LABEL" public "$FG" "$FA")
  for pair in "own_pub:$S_OWN_PUB" "own_priv:$S_OWN_PRIV" "foreign_priv:$S_FOR_PRIV" "foreign_pub:$S_FOR_PUB"; do
    name="${pair%%:*}"; id="${pair#*:}"
    R=$(tool supersede_claim "{\"claim_id\":\"$id\",\"content\":\"Batch H replacement for $name $LABEL\",\"truth_value\":0.6,\"reason\":\"probe\"}")
    echo "   $name: $(verdict "$R") | old_is_current=$(q "SELECT is_current FROM claims WHERE id='$id'") replacements=$(q "SELECT count(*) FROM claims WHERE supersedes='$id'")"
  done
fi

# ── theme_cluster ──────────────────────────────────────────────────────────
if want theme; then
  echo
  echo "=== theme_cluster: all or nothing, the previous themes survive a failed run ==="
  q "UPDATE claims SET theme_id = NULL WHERE theme_id IS NOT NULL; DELETE FROM claim_themes" >/dev/null
  PRIOR=$(q "INSERT INTO claim_themes (label, description) VALUES ('bh-prior-$LABEL', 'a theme from an earlier run') RETURNING id" | head -1)
  # Two well-separated directions, three public claims each, all owned by the
  # server agent's group: the population a stamp-free clusterer can reach.
  for i in 1 2 3; do
    for d in 0 1; do
      if [ "$d" = 0 ]; then V="('[0.9,'||array_to_string(array_fill(0.01::float8, ARRAY[1535]),',')||']')::vector"
      else V="('[0.01,0.9,'||array_to_string(array_fill(0.01::float8, ARRAY[1534]),',')||']')::vector"; fi
      q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id, embedding)
         VALUES (gen_random_uuid(), 'Batch H theme $d/$i $LABEL', decode(md5(random()::text)||md5(random()::text),'hex'), 0.6,
                 '$MA', ARRAY['bh-theme']::text[], 'public', '$OG', $V)" >/dev/null
    done
  done
  R=$(tool theme_cluster '{"k":2,"min_claims_per_theme":1,"wipe_first":true,"label_prefix":"bh"}')
  echo "   theme_cluster: $(verdict "$R") themes_created=$(field "$R" themes_created) claims_assigned=$(field "$R" claims_assigned) | themes=$(q "SELECT count(*) FROM claim_themes") prior_survives=$(q "SELECT count(*) FROM claim_themes WHERE id='$PRIOR'") themed_claims=$(q "SELECT count(*) FROM claims WHERE theme_id IS NOT NULL")"
fi

# ── maintenance tools ──────────────────────────────────────────────────────
if want maintenance; then
  echo
  echo "=== maintenance tools: FOREIGN-PRIVATE rows are the discriminator ==="
  # A stale cache on a foreign-private claim with a BBA (#395): recompute must
  # rewrite it, and claims_recomputed must count only real writes.
  RR=$(tool submit_claim '{"content":"Batch H recompute target","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.8,"novelty_threshold":0.0}')
  CR=$(field "$RR" claim_id)
  q "UPDATE claims SET visibility='group', owner_group_id='$FG' WHERE id='$CR'" >/dev/null
  # A foreign-private claim with no vector, for the backfill.
  C_EMB=$(seed "Batch H foreign private claim that needs an embedding $LABEL" group "$FG" "$FA")
  # A cross-group exact-restatement pair with identical vectors, for the sweep.
  VEC="('['||array_to_string(array_fill(0.01::float8, ARRAY[1536]),',')||']')::vector"
  HASH="decode(md5('bh-dup-$LABEL')||md5('bh-dup-$LABEL'),'hex')"
  D1=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id, embedding)
          VALUES (gen_random_uuid(), 'Batch H duplicate statement $LABEL', $HASH, 0.7, '$FA', ARRAY['bh-dup']::text[], 'group', '$FG', $VEC) RETURNING id" | head -1)
  D2=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id, embedding)
          VALUES (gen_random_uuid(), 'Batch H duplicate statement $LABEL', $HASH, 0.6, '$MA', ARRAY['bh-dup']::text[], 'group', '$OG', $VEC) RETURNING id" | head -1)
  reset_stale() { q "UPDATE claims SET belief=NULL, plausibility=NULL, pignistic_prob=NULL WHERE id='$CR'" >/dev/null; }
  maint_rows() {
    echo "recompute_cache=$(q "SELECT CASE WHEN belief IS NULL THEN 'STALE(NULL)' ELSE 'written:'||round(belief::numeric,4)::text END FROM claims WHERE id='$CR'") backfill_vector=$(q "SELECT CASE WHEN embedding IS NULL THEN 'NULL' ELSE 'present' END FROM claims WHERE id='$C_EMB'") dup_retired=$(q "SELECT count(*) FROM claims WHERE id IN ('$D1','$D2') AND is_current = false")"
  }
  if [ -z "$OPENAI_API_KEY" ]; then
    echo "   NOTE: OPENAI_API_KEY is unset, so the backfill case below measures the absence of a key, not the write path (README trap 4). Its verdict is not reported."
  fi
  for mode in none app maint fallback_bypass; do
    stop_server
    start_server "$mode"
    reset_stale
    q "UPDATE claims SET embedding=NULL WHERE id='$C_EMB'" >/dev/null
    q "UPDATE claims SET is_current=true, supersedes=NULL WHERE id IN ('$D1','$D2')" >/dev/null
    case "$mode" in
      none)  echo "--- MAINTENANCE_DATABASE_URL unset (expect: all three refuse loudly, rows unchanged)";;
      app)   echo "--- MAINTENANCE_DATABASE_URL = the app login (expect: all three refuse loudly, rows unchanged; this is the zero-row hybrid)";;
      maint) echo "--- MAINTENANCE_DATABASE_URL = a bypass-capable role (expect: all three work on FOREIGN rows)";;
      fallback_bypass) echo "--- MAINTENANCE_DATABASE_URL unset, APPLICATION DSN bypass-capable (expect: all three refuse loudly, rows unchanged; the fallback never enables them)";;
    esac
    R=$(tool recompute_beliefs "{\"claim_ids\":[\"$CR\"]}")
    echo "   recompute_beliefs: $(verdict "$R") claims_recomputed=$(field "$R" claims_recomputed) frame_writes=$(field "$R" frame_writes) | $(maint_rows)"
    R=$(tool sweep_semantic_duplicates '{"dry_run":false,"labels_scope":["bh-dup"],"similarity_threshold":0.05}')
    echo "   sweep_semantic_duplicates: $(verdict "$R") scanned=$(field "$R" scanned) pairs_marked=$(field "$R" pairs_marked) | $(maint_rows)"
    R=$(tool backfill_embeddings '{"limit":50}')
    if [ -n "$OPENAI_API_KEY" ]; then
      echo "   backfill_embeddings: $(verdict "$R") candidates=$(field "$R" candidates) embedded=$(field "$R" embedded) | $(maint_rows)"
    else
      echo "   backfill_embeddings: (no OPENAI_API_KEY; not reported)"
    fi
  done
fi

# ── maintenance tools over authenticated HTTP ──────────────────────────────
if want maint_auth; then
  echo
  echo "=== maintenance tools over AUTHENTICATED HTTP: the scope is the gate ==="
  JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  mint() {  # $1 agent id, $2 scopes (comma-separated). HS256 with this run's secret.
    SECRET="$JWT_SECRET" python3 - "$1" "$2" <<'PY'
import base64, hashlib, hmac, json, os, sys, time, uuid
agent, scopes = sys.argv[1], sys.argv[2].split(",")
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
now = int(time.time()) - 2
claims = {"sub": agent, "iss": "epigraph", "aud": "epigraph-api", "exp": now + 3600,
          "iat": now, "nbf": now, "jti": str(uuid.uuid4()), "scopes": scopes,
          "client_type": "service", "owner_id": agent, "agent_id": agent}
head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
body = b64(json.dumps(claims).encode())
sig = hmac.new(os.environ["SECRET"].encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
print(f"{head}.{body}.{b64(sig)}")
PY
  }
  # PEER: claims:write, a member of NO group that owns the duplicate pair.
  PEER=$(q "INSERT INTO agents (public_key, display_name) VALUES (decode(md5(random()::text)||md5(random()::text),'hex'), 'batch-h peer $LABEL') RETURNING id" | head -1)
  # A direction of its own: the sweep's neighbour search is corpus-wide, so a
  # direction another arm also uses (the maintenance pair's constant vector,
  # the theme arm's first and second axes) lets those rows crowd this pair out
  # of the neighbour list. MEASURED: pairs_marked=0 when this shared an axis.
  VEC="('[0.01,0.01,0.9,'||array_to_string(array_fill(0.01::float8, ARRAY[1533]),',')||']')::vector"
  HASH="decode(md5('bh-authdup-$LABEL')||md5('bh-authdup-$LABEL'),'hex')"
  A1=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id, embedding)
          VALUES (gen_random_uuid(), 'Batch H auth duplicate $LABEL', $HASH, 0.7, '$FA', ARRAY['bh-authdup']::text[], 'group', '$FG', $VEC) RETURNING id" | head -1)
  A2=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id, embedding)
          VALUES (gen_random_uuid(), 'Batch H auth duplicate $LABEL', $HASH, 0.6, '$MA', ARRAY['bh-authdup']::text[], 'group', '$OG', $VEC) RETURNING id" | head -1)
  auth_rows() { echo "retired=$(q "SELECT count(*) FROM claims WHERE id IN ('$A1','$A2') AND is_current = false")"; }
  for who in peer admin; do
    stop_server
    case "$who" in
      peer)  BEARER="$(mint "$PEER" claims:read,claims:write)";;
      admin) BEARER="$(mint "$PEER" claims:read,claims:write,claims:admin)";;
    esac
    start_server auth
    q "UPDATE claims SET is_current=true, supersedes=NULL WHERE id IN ('$A1','$A2')" >/dev/null
    case "$who" in
      peer)  echo "--- claims:write-only bearer, no membership (expect: every call Forbidden, no ids listed, nothing retired)";;
      admin) echo "--- claims:admin bearer (expect: admitted; the dry run lists the pair, the live run retires one)";;
    esac
    R=$(tool sweep_semantic_duplicates '{"dry_run":true,"labels_scope":["bh-authdup"],"similarity_threshold":0.05}')
    echo "   sweep dry_run: $(verdict "$R") scanned=$(field "$R" scanned) exact_clusters=$(field "$R" 'clusters | length') | $(auth_rows)"
    R=$(tool sweep_semantic_duplicates '{"dry_run":false,"labels_scope":["bh-authdup"],"similarity_threshold":0.05}')
    echo "   sweep live:    $(verdict "$R") pairs_marked=$(field "$R" pairs_marked) exact_clusters=$(field "$R" 'clusters | length') failures=$(field "$R" failures) | $(auth_rows)"
    R=$(tool recompute_beliefs '{"claim_ids":[]}')
    echo "   recompute_beliefs: $(verdict "$R")"
    R=$(tool backfill_embeddings '{"limit":1,"dry_run":true}')
    echo "   backfill_embeddings dry_run: $(verdict "$R")"
  done
  stop_server
  BEARER=""
  JWT_SECRET=""
fi

# ── caller_auth: batch H-b D1 + D2 over AUTHENTICATED HTTP ─────────────────
# The transport batch H-b changes. Every arm above runs unauthenticated, where
# the caller IS the server agent, so a write stamped from the wrong agent is
# invisible there. Here the server's signer (MA) is NOT the caller: a
# claims:write bearer for agent CA (own personal group CG) and a claims:admin
# bearer for agent AD whose token `sub` is an oauth_clients row granting it
# claims:admin (migration 111 re-checks exactly that record).
# `mint_as <sub> <agent> <scopes>`: HS256 with this run's secret.
mint_as() {
  SECRET="$JWT_SECRET" python3 - "$1" "$2" "$3" <<'PY'
import base64, hashlib, hmac, json, os, sys, time, uuid
sub, agent, scopes = sys.argv[1], sys.argv[2], sys.argv[3].split(",")
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
now = int(time.time()) - 2
claims = {"sub": sub, "iss": "epigraph", "aud": "epigraph-api", "exp": now + 3600,
          "iat": now, "nbf": now, "jti": str(uuid.uuid4()), "scopes": scopes,
          "client_type": "human", "owner_id": sub, "agent_id": agent}
head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
body = b64(json.dumps(claims).encode())
sig = hmac.new(os.environ["SECRET"].encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
print(f"{head}.{body}.{b64(sig)}")
PY
}
# A fresh agent with its personal group, minted through 105's definer.
new_agent() {
  local id
  id=$(q "INSERT INTO agents (public_key, display_name) VALUES (decode(md5(random()::text)||md5(random()::text),'hex'), 'batch-h-b $1 $LABEL') RETURNING id" | head -1)
  q "SELECT public.epigraph_ensure_personal_group('$id')" >/dev/null
  printf '%s' "$id"
}
personal_group() { q "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:$1'"; }
admin_audits() { q "SELECT count(*) FROM security_events WHERE event_type='claims.admin_write' AND agent_id='$1'"; }

if want caller_auth; then
  echo
  echo "=== caller_auth: authenticated MCP writes carry the CALLER's authority (D1) and the audited admin path (D2) ==="
  JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  CA=$(new_agent caller); CG=$(personal_group "$CA")
  AD=$(new_agent admin);  AG=$(personal_group "$AD")
  ADC=$(q "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, granted_scopes, status, agent_id)
          VALUES (gen_random_uuid(), 'bh-admin-'||gen_random_uuid(), 'batch-h-b admin', 'human',
                  ARRAY['claims:read','claims:write','claims:admin'], ARRAY['claims:read','claims:write','claims:admin'], 'active', '$AD') RETURNING id" | head -1)
  echo "### caller=$CA ($CG) admin=$AD ($AG, client $ADC) server signer=$MA foreign=$FA ($FG)"
  C_AUTH_FOR=$(seed "Batch H-b foreign public $LABEL" public "$FG" "$FA" "ARRAY['backlog']::text[]")
  C_AUTH_FOR2=$(seed "Batch H-b foreign public two $LABEL" public "$FG" "$FA" "ARRAY['backlog']::text[]")

  stop_server
  BEARER="$(mint_as "$(q "SELECT gen_random_uuid()")" "$CA" claims:read,claims:write)"
  start_server auth
  echo "--- claims:write bearer for the caller (expect A and B: authored+owned by the caller; own writes OK; foreign refused)"
  R=$(tool submit_claim "{\"content\":\"Batch H-b caller claim $LABEL\",\"methodology\":\"extraction\",\"evidence_data\":\"probe\",\"evidence_type\":\"empirical\",\"confidence\":0.7,\"novelty_threshold\":0.0}")
  CC=$(field "$R" claim_id)
  echo "   submit_claim: $(verdict "$R") | author=$(q "SELECT CASE agent_id WHEN '$CA' THEN 'CALLER' WHEN '$MA' THEN 'SERVER' ELSE agent_id::text END FROM claims WHERE id='$CC'") owner=$(q "SELECT CASE owner_group_id WHEN '$CG' THEN 'CALLER-GROUP' ELSE owner_group_id::text END FROM claims WHERE id='$CC'") signer=$(q "SELECT CASE signer_id WHEN '$MA' THEN 'SERVER' ELSE COALESCE(signer_id::text,'none') END FROM claims WHERE id='$CC'") bbas=$(q "SELECT count(*) FROM mass_functions WHERE claim_id='$CC'")"
  R=$(tool verify_claim "{\"claim_id\":\"$CC\"}")
  echo "   verify_claim: $(verdict "$R") signed=$(field "$R" signed) signature_valid=$(field "$R" signature_valid) hash_check=$(field "$R" hash_check)"
  R=$(tool patch_claim "{\"claim_id\":\"$CC\",\"properties\":{\"bhb\":1}}")
  echo "   patch_claim own: $(verdict "$R") | patched=$(q "SELECT count(*) FROM claims WHERE id='$CC' AND properties ? 'bhb'")"
  R=$(tool update_labels "{\"claim_id\":\"$CC\",\"add\":[\"resolved\"]}")
  echo "   update_labels own +resolved: $(verdict "$R") admin_path=$(field "$R" admin_path) | labelled=$(q "SELECT count(*) FROM claims WHERE id='$CC' AND 'resolved'=ANY(labels)")"
  R=$(tool patch_claim "{\"claim_id\":\"$C_AUTH_FOR\",\"properties\":{\"bhb\":1}}")
  echo "   patch_claim foreign: $(verdict "$R") | patched=$(q "SELECT count(*) FROM claims WHERE id='$C_AUTH_FOR' AND properties ? 'bhb'")"
  R=$(tool update_labels "{\"claim_id\":\"$C_AUTH_FOR\",\"add\":[\"resolved\"]}")
  echo "   update_labels foreign +resolved: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$C_AUTH_FOR' AND 'resolved'=ANY(labels)")"
  R=$(tool update_labels "{\"claim_id\":\"$C_AUTH_FOR\",\"add\":[\"bhb-free\"]}")
  echo "   update_labels foreign +free label (A and B: ERR, the whole mutation needs ownership over HTTP since the batch H-b review): $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$C_AUTH_FOR' AND 'bhb-free'=ANY(labels)")"
  echo "   non-admin audit rows: $(admin_audits "$CA")"

  stop_server
  BEARER="$(mint_as "$ADC" "$AD" claims:read,claims:write,claims:admin)"
  start_server auth
  echo "--- claims:admin bearer, a live grant on its client record (expect A and B: foreign relabel OK through the audited path, admin recorded)"
  BEFORE=$(admin_audits "$AD")
  R=$(tool update_labels "{\"claim_id\":\"$C_AUTH_FOR\",\"add\":[\"resolved\"]}")
  echo "   update_labels foreign +resolved: $(verdict "$R") admin_path=$(field "$R" admin_path) | labelled=$(q "SELECT count(*) FROM claims WHERE id='$C_AUTH_FOR' AND 'resolved'=ANY(labels)") audit $BEFORE->$(admin_audits "$AD") principal=$(q "SELECT CASE details->>'admin_agent_id' WHEN '$AD' THEN 'ADMIN' ELSE details->>'admin_agent_id' END FROM security_events WHERE event_type='claims.admin_write' AND agent_id='$AD' ORDER BY created_at DESC LIMIT 1") author_recorded_as=$(q "SELECT CASE details->>'claim_author' WHEN '$FA' THEN 'TARGET-AUTHOR' ELSE details->>'claim_author' END FROM security_events WHERE event_type='claims.admin_write' AND agent_id='$AD' ORDER BY created_at DESC LIMIT 1")"
  R=$(tool patch_claim "{\"claim_id\":\"$C_AUTH_FOR2\",\"properties\":{\"bhb_admin\":1},\"remove_labels\":[\"backlog\"]}")
  echo "   patch_claim foreign: $(verdict "$R") admin_path=$(field "$R" admin_path) | patched=$(q "SELECT count(*) FROM claims WHERE id='$C_AUTH_FOR2' AND properties ? 'bhb_admin' AND NOT ('backlog'=ANY(labels))") audit=$(admin_audits "$AD")"
  R=$(tool update_labels "{\"claim_id\":\"$C_FOR_PRIV2\",\"add\":[\"resolved\"]}")
  echo "   update_labels foreign PRIVATE (unreadable): $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$C_FOR_PRIV2' AND 'resolved'=ANY(labels)")"

  stop_server
  BEARER="$(mint_as "$(q "SELECT gen_random_uuid()")" "$AD" claims:read,claims:write,claims:admin)"
  start_server auth
  echo "--- claims:admin bearer whose sub is NOT a client record granting it (expect: refused, nothing written, no audit row)"
  BEFORE=$(admin_audits "$AD")
  q "UPDATE claims SET labels = ARRAY['backlog'] WHERE id='$C_AUTH_FOR'" >/dev/null
  R=$(tool update_labels "{\"claim_id\":\"$C_AUTH_FOR\",\"add\":[\"resolved\"]}")
  echo "   update_labels foreign +resolved: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$C_AUTH_FOR' AND 'resolved'=ANY(labels)") audit $BEFORE->$(admin_audits "$AD")"
  stop_server
  BEARER=""
  JWT_SECRET=""
fi

# ── op_http: #503's operator arm over AUTHENTICATED HTTP (merge report) ─────
# An HTTP MCP server on the APP DSN whose signer (MA) is unrelated to the
# operator, and a claims:read,claims:write bearer for the OPERATOR acting on
# public claims authored by its linked agent and owned by the operator's
# personal group (where #503 puts an operated agent's claims). Before batch H-b
# every call passed require_owner_or_admin's operator arm and then failed 42501
# on A with nothing written: the transaction was stamped from MA.
if want op_http; then
  echo
  echo "=== op_http: the operator's bearer on its linked agent's claims (expect A and B: OK, written) ==="
  JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  OP=$(new_agent operator); OPG=$(personal_group "$OP")
  LA=$(new_agent linked)
  q "SELECT public.epigraph_link_operator('$LA', '$OP')" >/dev/null
  echo "### operator=$OP ($OPG) linked=$LA link=$(q "SELECT count(*) FROM operator_links WHERE agent_id='$LA' AND operator_id='$OP'")"
  L1=$(seed "Batch H-b operated claim one $LABEL" public "$OPG" "$LA" "ARRAY['backlog']::text[]")
  L2=$(seed "Batch H-b operated claim two $LABEL" public "$OPG" "$LA" "ARRAY['backlog']::text[]")
  L3=$(seed "Batch H-b operated claim three $LABEL" public "$OPG" "$LA" "ARRAY['backlog']::text[]")
  stop_server
  BEARER="$(mint_as "$(q "SELECT gen_random_uuid()")" "$OP" claims:read,claims:write)"
  start_server auth
  R=$(tool patch_claim "{\"claim_id\":\"$L1\",\"properties\":{\"bhb_op\":1}}")
  echo "   patch_claim: $(verdict "$R") | patched=$(q "SELECT count(*) FROM claims WHERE id='$L1' AND properties ? 'bhb_op'")"
  R=$(tool update_labels "{\"claim_id\":\"$L2\",\"add\":[\"resolved\"]}")
  echo "   update_labels +resolved: $(verdict "$R") admin_path=$(field "$R" admin_path) | labelled=$(q "SELECT count(*) FROM claims WHERE id='$L2' AND 'resolved'=ANY(labels)")"
  R=$(tool resolve_backlog_item "{\"original_id\":\"$L3\",\"resolution_content\":\"retired by the operator over HTTP\"}")
  RES=$(field "$R" resolution_claim_id)
  echo "   resolve_backlog_item: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$L3' AND 'resolved'=ANY(labels)") resolution_author=$(q "SELECT CASE agent_id WHEN '$OP' THEN 'OPERATOR' WHEN '$MA' THEN 'SERVER' ELSE agent_id::text END FROM claims WHERE id='${RES:-00000000-0000-0000-0000-000000000000}'")"
  stop_server
  BEARER=""
  JWT_SECRET=""
fi

# ── review_http: the batch H-b review's authority attacks over AUTHENTICATED HTTP
# Each case names the finding it re-measures, prints the verdict AND the rows.
# Identities are per-run (agents and links survive TRUNCATE).
#   H3 lineage   a stranger ingests generation 1 of the victim's workflow with
#                NO parent (was: OK, recorded the stranger, then admitted it and
#                locked the victim out); expect ERR and 0 new rows, victim OK
#   H3 admin     add_step by a claims:admin token whose client grants nothing
#                (was: OK on the scope alone, no audit) and by one whose client
#                grants it (OK, one workflows.admin_write row)
#   labels       a teammate (writer of the team group owning the victim's
#                claim) relabels it with update_labels (was: OK) and patch_claim
#   attribution  create_perspective owner / publish_event actor = the victim
#   patch_edge   a stranger retires the victim's world-owned edge (was: OK)
#   reliability  set_source_reliability on a random uuid (was: OK over
#                nothing) and on the victim's perspective
wf_json() {  # $1 canonical, $2 generation, $3 summary, $4 step text
  printf '{"source":{"canonical_name":"%s","goal":"Review probe workflow %s","generation":%s,"authors":[],"tags":[],"metadata":{}},"thesis":"Review probe thesis %s %s","thesis_derivation":"TopDown","phases":[{"title":"Phase","summary":"%s","steps":[{"compound":"%s","rationale":"probe","operations":[],"generality":[1],"confidence":0.8}]}],"relationships":[]}' \
    "$1" "$1" "$2" "$1" "$2" "$3" "$4"
}
wf_rows() { q "SELECT string_agg(generation||':'||CASE metadata->>'epigraph_submitted_by' WHEN '$V' THEN 'VICTIM' WHEN '$ATK' THEN 'ATTACKER' ELSE COALESCE(metadata->>'epigraph_submitted_by','none') END, ' ' ORDER BY generation) FROM workflows WHERE canonical_name='$1'"; }
wf_steps() { q "SELECT count(*) FROM edges e JOIN workflows w ON w.id=e.source_id WHERE w.canonical_name='$1' AND e.relationship='executes'"; }
wf_audits() { q "SELECT count(*) FROM security_events WHERE event_type='workflows.admin_write' AND agent_id='$1'"; }
as_bearer() {  # $1 sub, $2 agent, $3 scopes
  stop_server
  BEARER="$(mint_as "$1" "$2" "$3")"
  start_server auth
}

if want review_http; then
  echo
  echo "=== review_http: the batch H-b review's authority attacks (expect A and B: every attack ERR, nothing written; every calibration OK) ==="
  JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  V=$(new_agent victim); ATK=$(new_agent attacker); TM=$(new_agent teammate); WA=$(new_agent wfadmin)
  WAC=$(q "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, granted_scopes, status, agent_id)
          VALUES (gen_random_uuid(), 'rv-wfadmin-'||gen_random_uuid(), 'review wf admin', 'human',
                  ARRAY['claims:read','claims:write','claims:admin'], ARRAY['claims:read','claims:write','claims:admin'], 'active', '$WA') RETURNING id" | head -1)
  TG=$(q "INSERT INTO groups (display_name, did_key, public_key, kind) VALUES ('review team $LABEL', 'did:rv:team:$LABEL:'||gen_random_uuid(), decode(repeat('ab',32),'hex'), 'team') RETURNING id" | head -1)
  q "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) VALUES ('$TG','$V','\\x00',0,'admin'), ('$TG','$TM','\\x00',0,'writer')" >/dev/null
  WF="rv-victim-wf-$LABEL"
  echo "### victim=$V attacker=$ATK teammate=$TM wfadmin=$WA (client $WAC) team=$TG"

  as_bearer "$(q "SELECT gen_random_uuid()")" "$V" claims:read,claims:write
  R=$(tool ingest_workflow "{\"extraction\":$(wf_json "$WF" 0 "victim gen0 $LABEL" "victim step one $LABEL")}")
  echo "   H3 victim ingest gen0: $(verdict "$R") | rows=$(wf_rows "$WF")"

  as_bearer "$(q "SELECT gen_random_uuid()")" "$ATK" claims:read,claims:write
  R=$(tool ingest_workflow "{\"extraction\":$(wf_json "$WF" 1 "attacker gen1 $LABEL" "attacker step $LABEL")}")
  echo "   H3 attacker ingest gen1, no parent (expect ERR): $(verdict "$R") | rows=$(wf_rows "$WF")"
  R=$(tool add_step "{\"canonical_name\":\"$WF\",\"step_text\":\"attacker add_step $LABEL\"}")
  echo "   H3 attacker add_step (expect ERR): $(verdict "$R") | steps=$(wf_steps "$WF")"

  as_bearer "$(q "SELECT gen_random_uuid()")" "$V" claims:read,claims:write
  R=$(tool add_step "{\"canonical_name\":\"$WF\",\"step_text\":\"victim add_step $LABEL\"}")
  echo "   H3 victim add_step (expect OK): $(verdict "$R") | steps=$(wf_steps "$WF")"

  as_bearer "$(q "SELECT gen_random_uuid()")" "$WA" claims:read,claims:write,claims:admin
  BEFORE=$(wf_steps "$WF")
  R=$(tool add_step "{\"canonical_name\":\"$WF\",\"step_text\":\"grantless admin step $LABEL\"}")
  echo "   H3 admin, NO client grant (expect ERR ADM02): $(verdict "$R") | steps $BEFORE->$(wf_steps "$WF") audits=$(wf_audits "$WA")"
  as_bearer "$WAC" "$WA" claims:read,claims:write,claims:admin
  R=$(tool add_step "{\"canonical_name\":\"$WF\",\"step_text\":\"granted admin step $LABEL\"}")
  echo "   H3 admin, live client grant (expect OK + 1 audit): $(verdict "$R") | steps=$(wf_steps "$WF") audits=$(wf_audits "$WA")"

  VC=$(seed "Review victim team claim $LABEL" public "$TG" "$V" "ARRAY['backlog']::text[]")
  as_bearer "$(q "SELECT gen_random_uuid()")" "$TM" claims:read,claims:write
  R=$(tool update_labels "{\"claim_id\":\"$VC\",\"add\":[\"wontfix\"],\"remove\":[\"backlog\"]}")
  echo "   labels teammate update_labels (expect ERR): $(verdict "$R") | labels=$(q "SELECT labels FROM claims WHERE id='$VC'")"
  R=$(tool patch_claim "{\"claim_id\":\"$VC\",\"remove_labels\":[\"backlog\"]}")
  echo "   labels teammate patch_claim (calibration, ERR): $(verdict "$R") | labels=$(q "SELECT labels FROM claims WHERE id='$VC'")"

  R=$(tool create_perspective "{\"name\":\"rv forged owner $LABEL\",\"owner_agent_id\":\"$V\"}")
  echo "   attribution create_perspective owner=victim (expect ERR): $(verdict "$R") | rows=$(q "SELECT count(*) FROM perspectives WHERE name='rv forged owner $LABEL'") perspective_of_victim=$(q "SELECT count(*) FROM edges e JOIN perspectives p ON p.id=e.source_id WHERE p.name='rv forged owner $LABEL' AND e.relationship='PERSPECTIVE_OF'")"
  R=$(tool publish_event "{\"event_type\":\"rv.forged.$LABEL\",\"actor_id\":\"$V\",\"payload\":{}}")
  echo "   attribution publish_event actor=victim (expect ERR): $(verdict "$R") | events=$(q "SELECT count(*) FROM events WHERE event_type='rv.forged.$LABEL'")"
  R=$(tool publish_event "{\"event_type\":\"rv.own.$LABEL\",\"payload\":{}}")
  echo "   attribution publish_event no actor (expect OK, actor=teammate): $(verdict "$R") | actor=$(q "SELECT CASE actor_id WHEN '$TM' THEN 'CALLER' ELSE COALESCE(actor_id::text,'none') END FROM events WHERE event_type='rv.own.$LABEL'")"

  VP1=$(seed "Review victim public one $LABEL" public "$(personal_group "$V")" "$V")
  VP2=$(seed "Review victim public two $LABEL" public "$(personal_group "$V")" "$V")
  VE=$(q "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ('$VP1','claim','$VP2','claim','decomposes_to','{}'::jsonb) RETURNING id" | head -1)
  as_bearer "$(q "SELECT gen_random_uuid()")" "$ATK" claims:read,claims:write
  R=$(tool patch_edge "{\"edge_id\":\"$VE\",\"valid_to\":\"2020-01-01T00:00:00Z\"}")
  echo "   patch_edge stranger on the victim's edge (owner_group=$(q "SELECT owner_group_id FROM edges WHERE id='$VE'" | cut -c1-8)) (expect ERR): $(verdict "$R") | valid_to=$(q "SELECT COALESCE(valid_to::text,'open') FROM edges WHERE id='$VE'")"

  R=$(tool set_source_reliability "{\"perspective_id\":\"$(q "SELECT gen_random_uuid()")\",\"source_reliability\":{\"empirical\":0.3}}")
  echo "   reliability random uuid (expect ERR not found): $(verdict "$R")"
  VPER=$(q "INSERT INTO perspectives (name, owner_agent_id, perspective_type, visibility, owner_group_id) VALUES ('rv victim lens $LABEL', '$V', 'analytical', 'public', '00000000-0000-0000-0000-000000000000') RETURNING id" | head -1)
  R=$(tool set_source_reliability "{\"perspective_id\":\"$VPER\",\"source_reliability\":{\"empirical\":0.3}}")
  echo "   reliability stranger on the victim's lens (expect ERR): $(verdict "$R") | stored=$(q "SELECT COALESCE(properties->>'source_reliability','none') FROM perspectives WHERE id='$VPER'")"
  stop_server
  BEARER=""
  JWT_SECRET=""
fi

# ── unauth_listener: the production socket shape (--allow-unauthenticated-http)
# The injected context carries every scope, claims:admin included, with a NIL
# client_id. The review measured these three as OK at BASE on B (orphan policy)
# and ERR ADM02 at the first H-b tip. Expect at this tip, A and B: ERR, nothing
# written — D2's rule (no admin principal to audit) — plus add_step on another
# submitter's workflow, which the scope alone no longer admits.
if want unauth_listener; then
  echo
  echo "=== unauth_listener: foreign writes through the injected claims:admin context (expect A and B: ERR, nothing written) ==="
  stop_server
  start_server none
  UF1=$(seed "Unauth foreign free-label $LABEL" public "$FG" "$FA" "ARRAY['backlog']::text[]")
  UF2=$(seed "Unauth foreign retire $LABEL" public "$FG" "$FA" "ARRAY['backlog']::text[]")
  UF3=$(seed "Unauth foreign resolve $LABEL" public "$FG" "$FA" "ARRAY['backlog']::text[]")
  R=$(tool update_labels "{\"claim_id\":\"$UF1\",\"add\":[\"ul-free\"]}")
  echo "   update_labels foreign +free: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$UF1' AND 'ul-free'=ANY(labels)")"
  R=$(tool update_labels "{\"claim_id\":\"$UF2\",\"add\":[\"resolved\"]}")
  echo "   update_labels foreign +resolved: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$UF2' AND 'resolved'=ANY(labels)")"
  R=$(tool resolve_backlog_item "{\"original_id\":\"$UF3\",\"resolution_content\":\"unauth listener probe $LABEL\"}")
  echo "   resolve_backlog_item foreign: $(verdict "$R") | item_resolved=$(q "SELECT count(*) FROM claims WHERE id='$UF3' AND 'resolved'=ANY(labels)") resolutions=$(q "SELECT count(*) FROM claims WHERE content LIKE 'Resolves $UF3:%'")"
  UWF="ul-wf-$LABEL"
  R=$(tool ingest_workflow "{\"extraction\":$(wf_json "$UWF" 0 "unauth gen0 $LABEL" "unauth step one $LABEL")}")
  q "UPDATE workflows SET metadata = COALESCE(NULLIF(metadata, 'null'::jsonb), '{}'::jsonb) || jsonb_build_object('epigraph_submitted_by', '$FA') WHERE canonical_name='$UWF'" >/dev/null
  echo "   (seeded $UWF: $(verdict "$R"), submitter re-recorded as the foreign agent)"
  R=$(tool add_step "{\"canonical_name\":\"$UWF\",\"step_text\":\"unauth step $LABEL\"}")
  echo "   add_step on a foreign submitter's workflow: $(verdict "$R") | steps=$(wf_steps "$UWF")"
  stop_server
fi

# ── cascade: supersede an OWN supporter of an own target O and a FOREIGN public
# target T whose edge BBA (public, foreign group) is seeded by the SU DSN. The
# review measured, first H-b tip, config A: T's edge BBA deleted (1 -> 0) while
# its belief stayed 0.7 (stale). Expect A: T keeps its BBA (1 -> 1) and belief,
# named in belief_cascade.errors; O repaired. B: both repaired, as before.
if want cascade; then
  echo
  echo "=== cascade: a supersede whose downstream includes a claim the caller cannot write ==="
  stop_server
  start_server none
  R=$(tool submit_claim "{\"content\":\"cascade source S $LABEL\",\"methodology\":\"extraction\",\"evidence_data\":\"probe\",\"evidence_type\":\"empirical\",\"confidence\":0.8,\"novelty_threshold\":0.0}")
  S=$(field "$R" claim_id)
  R=$(tool submit_claim "{\"content\":\"cascade own target O $LABEL\",\"methodology\":\"extraction\",\"evidence_data\":\"probe\",\"evidence_type\":\"empirical\",\"confidence\":0.6,\"novelty_threshold\":0.0}")
  O=$(field "$R" claim_id)
  T=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, owner_group_id, belief, plausibility, pignistic_prob) VALUES (gen_random_uuid(), 'cascade foreign target T $LABEL', decode(md5(random()::text)||md5(random()::text),'hex'), 0.6, '$FA', 'public', '$FG', 0.7, 0.9, 0.8) RETURNING id" | head -1)
  R=$(tool link_epistemic "{\"source_claim_id\":\"$S\",\"target_claim_id\":\"$O\",\"relationship\":\"supports\"}")
  EO=$(q "SELECT id FROM edges WHERE source_id='$S' AND target_id='$O' AND relationship='supports'")
  ET=$(q "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ('$S','claim','$T','claim','supports','{}'::jsonb) RETURNING id" | head -1)
  q "INSERT INTO perspectives (id, name, description, owner_agent_id, properties, perspective_type, frame_ids, extraction_method, confidence_calibration, owner_group_id, visibility) SELECT '$ET', name||' T', description, owner_agent_id, properties, perspective_type, frame_ids, extraction_method, confidence_calibration, '$FG', 'public' FROM perspectives WHERE id='$EO'" >/dev/null
  q "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, perspective_id, owner_group_id, visibility, combination_method, source_strength, evidence_type, locality_tag)
     SELECT '$T', frame_id, source_agent_id, masses, '$ET', '$FG', 'public', combination_method, source_strength, evidence_type, locality_tag FROM mass_functions WHERE perspective_id='$EO' LIMIT 1" >/dev/null
  q "INSERT INTO claim_frames (claim_id, frame_id) SELECT '$T', frame_id FROM mass_functions WHERE perspective_id='$EO' LIMIT 1 ON CONFLICT DO NOTHING" >/dev/null 2>&1
  echo "   before: O edge BBAs=$(q "SELECT count(*) FROM mass_functions WHERE perspective_id='$EO'") O belief=$(q "SELECT COALESCE(round(belief::numeric,2)::text,'NULL') FROM claims WHERE id='$O'") | T edge BBAs=$(q "SELECT count(*) FROM mass_functions WHERE perspective_id='$ET'") T belief=$(q "SELECT belief FROM claims WHERE id='$T'")"
  R=$(tool supersede_claim "{\"claim_id\":\"$S\",\"content\":\"cascade replacement for S $LABEL\",\"truth_value\":0.5,\"reason\":\"probe\"}")
  echo "   supersede: $(verdict "$R") | errors=$(printf '%s' "$R" | jq -c '.result.content[0].text | fromjson | .belief_cascade.errors | map(.[0:90])' 2>/dev/null) invalidated=$(field "$R" belief_cascade.invalidated_bbas)"
  echo "   after:  S current=$(q "SELECT is_current FROM claims WHERE id='$S'") O edge BBAs=$(q "SELECT count(*) FROM mass_functions WHERE perspective_id='$EO'") O belief=$(q "SELECT COALESCE(round(belief::numeric,2)::text,'NULL') FROM claims WHERE id='$O'") | T edge BBAs=$(q "SELECT count(*) FROM mass_functions WHERE perspective_id='$ET'") T belief=$(q "SELECT COALESCE(belief::text,'NULL') FROM claims WHERE id='$T'")"
  stop_server
fi

echo
echo "=== totals ==="
q "SELECT 'claims='||(SELECT count(*) FROM claims)||' edges='||(SELECT count(*) FROM edges)||' mass_functions='||(SELECT count(*) FROM mass_functions)||' events='||(SELECT count(*) FROM events)"
