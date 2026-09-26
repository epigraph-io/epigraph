#!/usr/bin/env bash
# Batch HTTP-id acceptance probe: WHO an HTTP MCP write is authored as, on the
# real binary as the real least-privilege role.
#
#   ./probe-httpid.sh <epigraph-mcp binary> <label> <a|b> [arm ...]
#
# Arms (default: all):
#   oauth     an authenticated (--jwt-secret) listener, a HUMAN principal (an
#             oauth_clients row of client_type 'human' whose agent has its own
#             personal group, the shape the authorization-code / consent flow
#             mints for): submit_claim, memorize and update_with_evidence, then
#             the author, owner group and signer of every row they wrote; then
#             the human retires its OWN backlog item over HTTP
#             (resolve_backlog_item, update_labels +resolved)
#   unauth    the --allow-unauthenticated-http listener (a principal-less
#             caller: every request gets the injected context naming the
#             listener's own signer): the same three writes, a claims:admin
#             tool, a read, and the principal-less caller's attempt to retire
#             the human's item; then, on a binary that has it, the same with
#             --allow-unauthenticated-writes (batch HTTP-id's opt-in)
#   retired   a FORMER shared signer: a listener key that served two principals
#             (so it carries OPERATED_BY auth-lineage edges to both), then
#             link-retired to the human through migration 107's
#             epigraph_link_retired_agent (refused: the shared-signer
#             fingerprint) and, when present, migration 116's attested variant;
#             then the human's bearer retires the former signer's backlog items
#             (one owned by the signer's personal group, one world-owned), on a
#             listener running a FRESH key
#   startup   a listener started under the retired former signer's key must
#             refuse to start, on both listener kinds
#
# Every line prints the tool verdict AND what the database holds after it.
# The bearer is HAND-MINTED (HS256 under a random per-run secret) with the claim
# shape /oauth/token issues; the /oauth/token mint path itself is not exercised
# here (see epigraph-api's oauth tests).
#
# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN     superuser DSN with DDL rights on the throwaway DB.
#   E2E_APP_DSN    the least-privilege application DSN (rolbypassrls=false).
# Optional:
#   E2E_MAINT_DSN  a login in epigraph_maintenance, for the link functions.
#                  Defaults to E2E_SU_DSN.
#   E2E_AGENT_KEY  32-byte hex seed for the listener's signer (public throwaway
#                  default). The `retired` arm derives two more per run.
#   E2E_OPERATOR_BIN  an `epigraph-operator` binary. When set, the `retired`
#                  arm records the attested link through its `link-retired
#                  --attest-shared-signer` (dry run, then --apply) instead of
#                  raw SQL, and, where the items are still open afterwards
#                  (config A), re-owns them with `reown-claims` and retires
#                  them again: the runbook's sequence, on the real binaries.
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
E2E_MAINT_DSN="${E2E_MAINT_DSN:-$E2E_SU_DSN}"
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
e2e_guard_dsn E2E_MAINT_DSN
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
E2E_AGENT_KEY="${E2E_AGENT_KEY:-000000000000000000000000000000000000000000000000000000000e2e5eed}"
# -----------------------------------------------------------------------------
set -uo pipefail
BIN="${1:?usage: probe-httpid.sh <binary> <label> <a|b> [arm ...]}"
LABEL="${2:?label}"
CFG="${3:?a|b}"
shift 3
ARMS="${*:-oauth unauth retired startup}"
command -v jq >/dev/null || { echo "probe-httpid.sh needs jq" >&2; exit 2; }
E2E="$(cd "$(dirname "$0")" && pwd)"
SOCK="$E2E/hid.sock.$LABEL"
LOG="$E2E/hid.$LABEL.log"
H=(-H Content-Type:application/json -H Accept:application/json,text/event-stream)
BEARER=""
JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"

q() { PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -X -tA -c "$1"; }
# The maintenance login: the link functions are EXECUTE-able by it only.
qm() { psql "$E2E_MAINT_DSN" -X -tA -v ON_ERROR_STOP=1 -c "$1" 2>&1; }
want() { case " $ARMS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

echo "### binary: $BIN"
echo "### arms: $ARMS"
LOCKFIFO="$E2E/.hidlock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"
release_lock() { exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO"; }
echo "### serialized on advisory lock 918273645"

"$E2E/set-config.sh" "$CFG" >/dev/null 2>&1
echo "### $(q "SELECT 'config: ' || CASE WHEN EXISTS(SELECT 1 FROM pg_policy WHERE polname='claims_privacy') THEN 'B (prod-faithful)' ELSE 'A (clean series)' END") | migration head $(q "SELECT max(version) FROM _sqlx_migrations")"
q "TRUNCATE claims, evidence, edges, reasoning_traces, mass_functions, claim_frames,
           recall_events, challenges, events, workflows, papers CASCADE;" >/dev/null 2>&1

PID=""
# start_server <auth|unauth> <seed hex> ; returns non-zero if the socket never appears
start_server() {
  local mode="$1" key="$2"
  rm -f "$SOCK"
  case "$mode" in
    auth)   env -u MAINTENANCE_DATABASE_URL EPIGRAPH_JWT_SECRET="$JWT_SECRET" DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
              --agent-key "$key" --listen "unix:$SOCK" >> "$LOG" 2>&1 & ;;
    unauth) env -u MAINTENANCE_DATABASE_URL -u EPIGRAPH_JWT_SECRET DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
              --agent-key "$key" --listen "unix:$SOCK" --allow-unauthenticated-http >> "$LOG" 2>&1 & ;;
    unauthw) env -u MAINTENANCE_DATABASE_URL -u EPIGRAPH_JWT_SECRET DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn "$BIN" \
              --agent-key "$key" --listen "unix:$SOCK" --allow-unauthenticated-http --allow-unauthenticated-writes >> "$LOG" 2>&1 & ;;
  esac
  PID=$!
  for _ in $(seq 1 40); do
    [ -S "$SOCK" ] && break
    kill -0 "$PID" 2>/dev/null || break
    sleep 1
  done
  [ -S "$SOCK" ] || return 1
  curl -s --unix-socket "$SOCK" "${H[@]}" ${BEARER:+-H "Authorization: Bearer $BEARER"} -X POST http://localhost/mcp -D "$E2E/hidh.$LABEL" -o /dev/null \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"httpid-probe","version":"1"}}}'
  SID=$(grep -i '^mcp-session-id:' "$E2E/hidh.$LABEL" | tr -d '\r' | cut -d' ' -f2)
  # A notification has no response body, so `call`'s grep exits 1 here; that
  # is not a start-up failure.
  call '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null || true
  return 0
}
stop_server() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; }
: > "$LOG"
trap 'stop_server; release_lock' EXIT

call() { curl -s --unix-socket "$SOCK" "${H[@]}" ${BEARER:+-H "Authorization: Bearer $BEARER"} -H "mcp-session-id: $SID" \
           -X POST http://localhost/mcp -d "$1" | grep '^data: {' | tail -1 | sed 's/^data: //'; }
tool() { call "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"; }
verdict() {
  printf '%s' "$1" | jq -r '
    if .error then "ERR: " + (.error.message // "" | .[0:170])
    elif .result.isError then "TOOLERR: " + ((.result.content[0].text // "") | .[0:170])
    else "OK" end' 2>/dev/null || echo "UNPARSEABLE: ${1:0:120}"
}
field() { printf '%s' "$1" | jq -r ".result.content[0].text | fromjson | .$2 | if . == null then empty else tostring end" 2>/dev/null; }

# mint_as <sub> <agent> <scopes> <client_type>: HS256 with this run's secret,
# the claim shape /oauth/token issues.
mint_as() {
  SECRET="$JWT_SECRET" python3 - "$1" "$2" "$3" "$4" <<'PY'
import base64, hashlib, hmac, json, os, sys, time, uuid
sub, agent, scopes, ctype = sys.argv[1], sys.argv[2], sys.argv[3].split(","), sys.argv[4]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
now = int(time.time()) - 2
claims = {"sub": sub, "iss": "epigraph", "aud": "epigraph-api", "exp": now + 3600,
          "iat": now, "nbf": now, "jti": str(uuid.uuid4()), "scopes": scopes,
          "client_type": ctype, "owner_id": None, "agent_id": agent}
head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
body = b64(json.dumps(claims).encode())
sig = hmac.new(os.environ["SECRET"].encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
print(f"{head}.{body}.{b64(sig)}")
PY
}
new_agent() {
  local id
  id=$(q "INSERT INTO agents (public_key, display_name) VALUES (decode(md5(random()::text)||md5(random()::text),'hex'), 'httpid $1 $LABEL') RETURNING id" | head -1)
  q "SELECT public.epigraph_ensure_personal_group('$id')" >/dev/null
  printf '%s' "$id"
}
new_client() {  # $1 agent, $2 client_type -> oauth_clients.id
  # A 'service' row must name a legal entity (services_must_have_legal_entity).
  local le="NULL" lc="NULL"
  [ "$2" = service ] && { le="'httpid probe'"; lc="'probe@example.invalid'"; }
  q "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, granted_scopes, status, agent_id, legal_entity_name, legal_contact_email)
     VALUES (gen_random_uuid(), 'httpid-'||gen_random_uuid(), 'httpid $2 $LABEL', '$2',
             ARRAY['claims:read','claims:write'], ARRAY['claims:read','claims:write'], 'active', '$1', $le, $lc) RETURNING id" | head -1
}
personal_group() { q "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:$1'"; }
# A per-run seed, so an agent that a previous run link-retired is never reused
# (agents and links survive TRUNCATE).
run_seed() { python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "httpid-$1-$LABEL-$(date +%s%N)"; }
agent_of_seed() {  # the agents.id registered for a seed's public key
  local pk
  pk=$(python3 - "$1" <<'PY'
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[1]))
print(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
PY
)
  q "SELECT id FROM agents WHERE public_key = decode('$pk','hex')"
}
name() {  # label a uuid against this run's cast
  case "$1" in
    "$HU") echo HUMAN ;; "$SIG") echo SIGNER ;; "$HG") echo HUMAN-GROUP ;; "$SG") echo SIGNER-GROUP ;;
    "") echo none ;; *) echo "other:${1:0:8}" ;;
  esac
}
SUBMIT='{"content":"CONTENT","methodology":"extraction","evidence_data":"probe","evidence_type":"empirical","confidence":0.7,"novelty_threshold":0.0}'
submit_json() { printf '%s' "$SUBMIT" | sed "s/CONTENT/$1/"; }

# The cast: a human principal HU with its personal group HG and a 'human'
# oauth_clients row HC; the listener's signer SIG, registered by a first boot.
HU=$(new_agent human); HG=$(personal_group "$HU"); HC=$(new_client "$HU" human)
start_server unauth "$E2E_AGENT_KEY" || { echo "FAIL: listener never started"; tail -20 "$LOG"; exit 1; }
tool query_claims '{"limit":1}' >/dev/null
stop_server
SIG=$(agent_of_seed "$E2E_AGENT_KEY"); SG=$(personal_group "$SIG")
echo "### human=$HU group=$HG client=$HC | listener signer=$SIG group=$SG"
[ -n "$HU" ] && [ -n "$HG" ] && [ -n "$HC" ] && [ -n "$SIG" ] || { echo "FAIL: cast did not seed"; exit 1; }

writes() {  # $1 tag: submit_claim, memorize, update_with_evidence; prints authors
  local R C M
  R=$(tool submit_claim "$(submit_json "httpid $1 submit $LABEL")")
  C=$(field "$R" claim_id)
  echo "   submit_claim: $(verdict "$R") | author=$(name "$(q "SELECT agent_id FROM claims WHERE id='${C:-00000000-0000-0000-0000-000000000000}'")") owner=$(name "$(q "SELECT owner_group_id FROM claims WHERE id='${C:-00000000-0000-0000-0000-000000000000}'")") signer=$(name "$(q "SELECT signer_id FROM claims WHERE id='${C:-00000000-0000-0000-0000-000000000000}'")")"
  R=$(tool memorize "{\"content\":\"httpid $1 memorize $LABEL\",\"confidence\":0.6,\"novelty_threshold\":0.0}")
  M=$(field "$R" claim_id)
  echo "   memorize: $(verdict "$R") | author=$(name "$(q "SELECT agent_id FROM claims WHERE id='${M:-00000000-0000-0000-0000-000000000000}'")") owner=$(name "$(q "SELECT owner_group_id FROM claims WHERE id='${M:-00000000-0000-0000-0000-000000000000}'")")"
  local T="${C:-$2}"
  local BEFORE_EV
  BEFORE_EV=$(q "SELECT count(*) FROM evidence WHERE claim_id='${T:-00000000-0000-0000-0000-000000000000}'")
  R=$(tool update_with_evidence "{\"claim_id\":\"${T:-00000000-0000-0000-0000-000000000000}\",\"evidence_data\":\"httpid $1 evidence $LABEL\",\"evidence_type\":\"empirical\",\"supports\":true,\"strength\":0.6,\"labels\":[]}")
  echo "   update_with_evidence: $(verdict "$R") | evidence $BEFORE_EV->$(q "SELECT count(*) FROM evidence WHERE claim_id='${T:-00000000-0000-0000-0000-000000000000}'") newest evidence owner=$(name "$(q "SELECT owner_group_id FROM evidence WHERE claim_id='${T:-00000000-0000-0000-0000-000000000000}' ORDER BY created_at DESC LIMIT 1")") signer=$(name "$(q "SELECT signer_id FROM evidence WHERE claim_id='${T:-00000000-0000-0000-0000-000000000000}' ORDER BY created_at DESC LIMIT 1")") mass source=$(name "$(q "SELECT source_agent_id FROM mass_functions WHERE claim_id='${T:-00000000-0000-0000-0000-000000000000}' ORDER BY created_at DESC LIMIT 1")")"
  LAST_CLAIM="$C"
}

# ── oauth ────────────────────────────────────────────────────────────────────
HUMAN_ITEM=""
if want oauth; then
  echo
  echo "=== oauth: a HUMAN principal over authenticated HTTP (expect: authored by HUMAN, owned by HUMAN-GROUP, signed by SIGNER) ==="
  BEARER="$(mint_as "$HC" "$HU" claims:read,claims:write human)"
  start_server auth "$E2E_AGENT_KEY" || { echo "FAIL: auth listener"; tail -20 "$LOG"; exit 1; }
  writes oauth
  echo "--- the human retires its OWN backlog items over HTTP (expect: OK, labelled, resolution authored by HUMAN)"
  R=$(tool submit_claim "{\"content\":\"httpid human backlog one $LABEL\",\"methodology\":\"extraction\",\"evidence_data\":\"probe\",\"evidence_type\":\"empirical\",\"confidence\":0.7,\"novelty_threshold\":0.0,\"labels\":[\"backlog\"]}")
  B1=$(field "$R" claim_id)
  R=$(tool submit_claim "{\"content\":\"httpid human backlog two $LABEL\",\"methodology\":\"extraction\",\"evidence_data\":\"probe\",\"evidence_type\":\"empirical\",\"confidence\":0.7,\"novelty_threshold\":0.0,\"labels\":[\"backlog\"]}")
  B2=$(field "$R" claim_id)
  HUMAN_ITEM="$B2"
  R=$(tool resolve_backlog_item "{\"original_id\":\"${B1:-00000000-0000-0000-0000-000000000000}\",\"resolution_content\":\"httpid resolved by the human $LABEL\"}")
  RES=$(field "$R" resolution_claim_id)
  echo "   resolve_backlog_item own: $(verdict "$R") | item labelled=$(q "SELECT count(*) FROM claims WHERE id='${B1:-00000000-0000-0000-0000-000000000000}' AND 'resolved'=ANY(labels)") resolution author=$(name "$(q "SELECT agent_id FROM claims WHERE id='${RES:-00000000-0000-0000-0000-000000000000}'")")"
  stop_server
  BEARER=""
fi

# ── unauth ───────────────────────────────────────────────────────────────────
unauth_arm() {  # $1 = unauth | unauthw
  start_server "$1" "$E2E_AGENT_KEY" || { echo "FAIL: unauth listener"; tail -20 "$LOG"; exit 1; }
  CL_BEFORE=$(q "SELECT count(*) FROM claims WHERE agent_id='$SIG'")
  writes "$1" "$HUMAN_ITEM"
  echo "   claims authored by SIGNER: $CL_BEFORE->$(q "SELECT count(*) FROM claims WHERE agent_id='$SIG'")"
  R=$(tool sweep_semantic_duplicates '{"dry_run":true}')
  echo "   sweep_semantic_duplicates (a claims:admin tool): $(verdict "$R")"
  R=$(tool query_claims '{"limit":1}')
  echo "   query_claims (a read): $(verdict "$R")"
  if [ -n "$HUMAN_ITEM" ]; then
    R=$(tool update_labels "{\"claim_id\":\"$HUMAN_ITEM\",\"add\":[\"resolved\"]}")
    echo "   update_labels +resolved on the HUMAN's item: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$HUMAN_ITEM' AND 'resolved'=ANY(labels)")"
    R=$(tool resolve_backlog_item "{\"original_id\":\"$HUMAN_ITEM\",\"resolution_content\":\"httpid principal-less resolve $LABEL\"}")
    echo "   resolve_backlog_item on the HUMAN's item: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$HUMAN_ITEM' AND 'resolved'=ANY(labels)") resolutions=$(q "SELECT count(*) FROM claims WHERE content LIKE 'Resolves $HUMAN_ITEM:%'")"
  fi
  stop_server
}
if want unauth; then
  echo
  echo "=== unauth: a PRINCIPAL-LESS caller on --allow-unauthenticated-http (the default) ==="
  unauth_arm unauth
  if "$BIN" --help 2>/dev/null | grep -q -- --allow-unauthenticated-writes; then
    echo "--- the same listener with --allow-unauthenticated-writes (expect: writes authored by the unlinked SIGNER; the human's item still refused)"
    unauth_arm unauthw
  else
    echo "   (this binary has no --allow-unauthenticated-writes: every write above ran on the pre-HTTP-id listener)"
  fi
fi

# ── retired ──────────────────────────────────────────────────────────────────
OLD_KEY=""
if want retired; then
  echo
  echo "=== retired: a former shared signer, link-retired to the human ==="
  OLD_KEY=$(run_seed old); NEW_KEY=$(run_seed new)
  SV=$(new_agent service); SVC=$(new_client "$SV" service)
  # Two principals through the OLD key: the shared-signer fingerprint.
  BEARER="$(mint_as "$HC" "$HU" claims:read,claims:write human)"
  start_server auth "$OLD_KEY" || { echo "FAIL: old-key listener"; tail -20 "$LOG"; exit 1; }
  tool query_claims '{"limit":1}' >/dev/null
  stop_server
  BEARER="$(mint_as "$SVC" "$SV" claims:read,claims:write service)"
  start_server auth "$OLD_KEY" || { echo "FAIL: old-key listener"; tail -20 "$LOG"; exit 1; }
  tool query_claims '{"limit":1}' >/dev/null
  stop_server
  BEARER=""
  OLD=$(agent_of_seed "$OLD_KEY"); OG=$(personal_group "$OLD")
  WORLD=$(q "SELECT id FROM groups WHERE did_key='did:epigraph:world'")
  echo "### former signer=$OLD group=$OG lineage targets=$(q "SELECT count(DISTINCT target_id) FROM edges WHERE source_id='$OLD' AND relationship='OPERATED_BY'") service=$SV"
  # Its backlog items as the pre-change listeners left them: authored by the
  # signer, public, owned by its personal group or by the world group.
  I1=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id) VALUES (gen_random_uuid(), 'httpid former-signer item personal $LABEL', decode(md5(random()::text)||md5(random()::text),'hex'), 0.6, '$OLD', ARRAY['backlog'], 'public', '$OG') RETURNING id" | head -1)
  I2=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id) VALUES (gen_random_uuid(), 'httpid former-signer item world $LABEL', decode(md5(random()::text)||md5(random()::text),'hex'), 0.6, '$OLD', ARRAY['backlog'], 'public', '$WORLD') RETURNING id" | head -1)
  I3=$(q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, visibility, owner_group_id) VALUES (gen_random_uuid(), 'httpid former-signer item resolve $LABEL', decode(md5(random()::text)||md5(random()::text),'hex'), 0.6, '$OLD', ARRAY['backlog'], 'public', '$OG') RETURNING id" | head -1)

  echo "--- before any link: the human's bearer on the former signer's item (expect: ERR, not the author, no operator)"
  BEARER="$(mint_as "$HC" "$HU" claims:read,claims:write human)"
  start_server auth "$NEW_KEY" || { echo "FAIL: new-key listener"; tail -20 "$LOG"; exit 1; }
  R=$(tool update_labels "{\"claim_id\":\"$I1\",\"add\":[\"resolved\"]}")
  echo "   update_labels +resolved: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$I1' AND 'resolved'=ANY(labels)")"
  stop_server

  echo "--- 107 epigraph_link_retired_agent(former signer, human) on the maintenance login"
  echo "   $(qm "SELECT link_created, link_retired, membership_live FROM public.epigraph_link_retired_agent('$OLD','$HU')" | head -1 | cut -c1-200)"
  echo "   links: $(q "SELECT count(*) FROM operator_links WHERE agent_id='$OLD'")"
  if [ -n "$(q "SELECT to_regprocedure('public.epigraph_link_retired_shared_signer(uuid,uuid,uuid[])')")" ]; then
    echo "--- 116 attested variant, attesting only the human (expect: refused, the service principal is unattested)"
    echo "   $(qm "SELECT link_created, link_retired, membership_live FROM public.epigraph_link_retired_shared_signer('$OLD','$HU',ARRAY['$HU']::uuid[])" | head -1 | cut -c1-200)"
    echo "   links: $(q "SELECT count(*) FROM operator_links WHERE agent_id='$OLD'")"
    echo "--- 116 attested variant, attesting the service principal (expect: linked, retired, no membership, one audit row)"
    if [ -n "${E2E_OPERATOR_BIN:-}" ]; then
      # The real operator CLI on the maintenance DSN: a dry run, then --apply.
      printf '%s\n' "$OLD" > "$E2E/hid.agents.$LABEL"
      EPIGRAPH_OPERATOR_MAINTENANCE_DSN="$E2E_MAINT_DSN" "$E2E_OPERATOR_BIN" link-retired \
        --agents-file "$E2E/hid.agents.$LABEL" --operator "$HU" --attest-shared-signer "$SV" 2>/dev/null \
        | sed 's/^/   CLI dry run: /' | cut -c1-160
      echo "   links after the dry run: $(q "SELECT count(*) FROM operator_links WHERE agent_id='$OLD'")"
      EPIGRAPH_OPERATOR_MAINTENANCE_DSN="$E2E_MAINT_DSN" "$E2E_OPERATOR_BIN" link-retired \
        --agents-file "$E2E/hid.agents.$LABEL" --operator "$HU" --attest-shared-signer "$SV" --apply 2>/dev/null \
        | sed 's/^/   CLI apply: /' | cut -c1-160
      echo "   CLI exit=${PIPESTATUS[0]}"
      rm -f "$E2E/hid.agents.$LABEL"
    else
      echo "   $(qm "SELECT link_created, link_retired, membership_live FROM public.epigraph_link_retired_shared_signer('$OLD','$HU',ARRAY['$SV']::uuid[])" | head -1 | cut -c1-200)"
    fi
    echo "   links: $(q "SELECT string_agg(CASE operator_id WHEN '$HU' THEN 'HUMAN' ELSE operator_id::text END||' retired='||retired, ',') FROM operator_links WHERE agent_id='$OLD'") memberships in human group=$(q "SELECT count(*) FROM group_memberships m JOIN groups g ON g.id=m.group_id WHERE m.agent_id='$OLD' AND g.did_key='did:epigraph:personal:$HU' AND m.revoked_at IS NULL") audit=$(q "SELECT count(*) FROM security_events WHERE event_type='operator.shared_signer_retired' AND agent_id='$OLD'")"
  else
    echo "   (migration 116 absent: no attested variant on this database)"
  fi

  echo "--- after the link: the human's bearer on a FRESH-key listener retires the former signer's items"
  start_server auth "$NEW_KEY" || { echo "FAIL: new-key listener"; tail -20 "$LOG"; exit 1; }
  R=$(tool update_labels "{\"claim_id\":\"$I1\",\"add\":[\"resolved\"]}")
  echo "   update_labels +resolved, owned by the former signer's group: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$I1' AND 'resolved'=ANY(labels)")"
  R=$(tool update_labels "{\"claim_id\":\"$I2\",\"add\":[\"resolved\"]}")
  echo "   update_labels +resolved, world-owned: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$I2' AND 'resolved'=ANY(labels)")"
  R=$(tool resolve_backlog_item "{\"original_id\":\"$I3\",\"resolution_content\":\"httpid former-signer item resolved by the human $LABEL\"}")
  RES=$(field "$R" resolution_claim_id)
  echo "   resolve_backlog_item, owned by the former signer's group: $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$I3' AND 'resolved'=ANY(labels)") resolution author=$(name "$(q "SELECT agent_id FROM claims WHERE id='${RES:-00000000-0000-0000-0000-000000000000}'")")"
  stop_server
  OPEN=$(q "SELECT count(*) FROM claims WHERE id IN ('$I1','$I2','$I3') AND NOT ('resolved'=ANY(labels))")
  if [ "$OPEN" != "0" ] && [ -n "${E2E_OPERATOR_BIN:-}" ] && [ "$(q "SELECT count(*) FROM operator_links WHERE agent_id='$OLD'")" != "0" ]; then
    # On a clean schema the operator's stamp cannot write a row owned by the
    # former signer's group or by the world group. The runbook's answer is to
    # re-own the items into the operator's group first (epigraph-operator
    # reown-claims, which accepts claims whose author has a retired link).
    echo "--- $OPEN still open: re-own them into the human's group (reown-claims --derived follow-claim), then retire over HTTP again"
    printf '%s\n%s\n%s\n' "$I1" "$I2" "$I3" > "$E2E/hid.claims.$LABEL"
    rm -f "$E2E/hid.manifest.$LABEL.jsonl"
    # reown-claims must SET SESSION AUTHORIZATION epigraph_app for its
    # readability invariant, which only a superuser login may: the SU DSN.
    EPIGRAPH_OPERATOR_MAINTENANCE_DSN="$E2E_SU_DSN" "$E2E_OPERATOR_BIN" reown-claims \
      --claims-file "$E2E/hid.claims.$LABEL" --operator "$HU" --derived follow-claim \
      --manifest-out "$E2E/hid.manifest.$LABEL.jsonl" --apply 2>&1 | tail -4 | sed 's/^/   reown: /' | cut -c1-160
    echo "   owners now: $(q "SELECT string_agg(CASE owner_group_id WHEN '$HG' THEN 'HUMAN-GROUP' ELSE owner_group_id::text END, ',') FROM claims WHERE id IN ('$I1','$I2','$I3')")"
    start_server auth "$NEW_KEY" || { echo "FAIL: new-key listener"; tail -20 "$LOG"; exit 1; }
    R=$(tool update_labels "{\"claim_id\":\"$I1\",\"add\":[\"resolved\"]}")
    echo "   update_labels +resolved (was the former signer's group): $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$I1' AND 'resolved'=ANY(labels)")"
    R=$(tool update_labels "{\"claim_id\":\"$I2\",\"add\":[\"resolved\"]}")
    echo "   update_labels +resolved (was world-owned): $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$I2' AND 'resolved'=ANY(labels)")"
    R=$(tool resolve_backlog_item "{\"original_id\":\"$I3\",\"resolution_content\":\"httpid former-signer item resolved after reown $LABEL\"}")
    RES=$(field "$R" resolution_claim_id)
    echo "   resolve_backlog_item (was the former signer's group): $(verdict "$R") | labelled=$(q "SELECT count(*) FROM claims WHERE id='$I3' AND 'resolved'=ANY(labels)") resolution author=$(name "$(q "SELECT agent_id FROM claims WHERE id='${RES:-00000000-0000-0000-0000-000000000000}'")")"
    stop_server
    rm -f "$E2E/hid.claims.$LABEL" "$E2E/hid.manifest.$LABEL.jsonl"
  fi
  BEARER=""
fi

# ── startup ──────────────────────────────────────────────────────────────────
if want startup; then
  echo
  echo "=== startup: a listener under a link-retired signer's key must refuse to start ==="
  if [ -z "$OLD_KEY" ] || [ "$(q "SELECT count(*) FROM operator_links l JOIN agents a ON a.id=l.agent_id WHERE a.id='$(agent_of_seed "$OLD_KEY")'")" = "0" ]; then
    # No link from the retired arm (e.g. no 116): link a fresh single-principal signer.
    OLD_KEY=$(run_seed solo)
    start_server unauth "$OLD_KEY" >/dev/null || true; stop_server
    OLD=$(agent_of_seed "$OLD_KEY")
    q "DELETE FROM edges WHERE source_id='$OLD' AND relationship='OPERATED_BY'" >/dev/null
    echo "   (linked a single-principal signer through 107: $(qm "SELECT link_retired FROM public.epigraph_link_retired_agent('$OLD','$HU')" | head -1 | cut -c1-120))"
  fi
  for mode in auth unauth; do
    : > "$LOG.start"
    rm -f "$SOCK"
    case "$mode" in
      auth)   EPIGRAPH_JWT_SECRET="$JWT_SECRET" DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn timeout 30 "$BIN" --agent-key "$OLD_KEY" --listen "unix:$SOCK" > "$LOG.start" 2>&1 & ;;
      unauth) env -u EPIGRAPH_JWT_SECRET DATABASE_URL="$E2E_APP_DSN" RUST_LOG=warn timeout 30 "$BIN" --agent-key "$OLD_KEY" --listen "unix:$SOCK" --allow-unauthenticated-http > "$LOG.start" 2>&1 & ;;
    esac
    SP=$!
    for _ in $(seq 1 25); do [ -S "$SOCK" ] && break; kill -0 "$SP" 2>/dev/null || break; sleep 1; done
    if [ -S "$SOCK" ]; then
      echo "   $mode listener: STARTED (socket up)"; kill "$SP" 2>/dev/null
    else
      wait "$SP"; echo "   $mode listener: REFUSED exit=$? | $(grep -o 'retired link\|acting link\|operator link[^.]*' "$LOG.start" | head -1)"
    fi
    wait "$SP" 2>/dev/null
  done
  rm -f "$LOG.start"
fi

echo
echo "=== totals ==="
q "SELECT 'claims='||(SELECT count(*) FROM claims)||' evidence='||(SELECT count(*) FROM evidence)||' mass_functions='||(SELECT count(*) FROM mass_functions)"
