#!/usr/bin/env bash
# HTTP arm: PATCH /api/v1/claims/:id/labels on the real `server` binary, as the
# real least-privilege role, on both schema configurations.
#
#   ./probe-http-labels.sh <epigraph-api server binary> <label> <a|b>
#
# WHY THIS PROBE EXISTS. Every other script in this directory drives the MCP
# binary; nothing drove an HTTP write route under a role RLS filters. The
# in-process API tests cannot: they connect as a superuser, and
# `epigraph_bypass()` keys on `session_user`, so every write they make is
# admitted whatever the route stamps. This is the only place the route's
# config-A behaviour is observable.
#
# Callers (JWTs minted here, HS256, with a secret generated per run):
#   OWNER  claims:write, the author of the OWN claims
#   ADMIN  claims:write + claims:admin, a writer of no group but its own
#   PEER   claims:write, neither
#
# Rows (every one seeded through the SU DSN, then relabelled once):
#   own-public       OWNER's claim, public, owned by OWNER's personal group
#   own-private      OWNER's claim, visibility=group, same owner
#   other-public     STRANGER's claim, public, owned by STRANGER's personal group
#   foreign-private  STRANGER's claim, visibility=group, owned by a team group
#                    ADMIN is not in
#   world-public     STRANGER's claim, public, owned by the WORLD group, which no
#                    viewer can write
# Each line prints the HTTP status AND whether the label is on the row
# afterwards, read back through the SU DSN: a 200 over an unchanged row and an
# error over a changed one are both failures that only the row reveals.
#
# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB.
#   E2E_APP_DSN  the least-privilege application DSN the server connects as.
#                MUST be a role with rolbypassrls=false, or every arm is vacuous.
# Optional:
#   E2E_MAINT_DSN  the server's MAINTENANCE_DATABASE_URL (its job pool refuses a
#                  non-bypassing one). Defaults to E2E_SU_DSN.
#   E2E_HTTP_PORT  port for the server under test. Default 18097.
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
E2E_MAINT_DSN="${E2E_MAINT_DSN:-$E2E_SU_DSN}"
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
e2e_guard_dsn E2E_MAINT_DSN
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
PORT="${E2E_HTTP_PORT:-18097}"
# -----------------------------------------------------------------------------
set -uo pipefail
BIN="${1:?usage: probe-http-labels.sh <server binary> <label> <a|b>}"
LABEL="${2:?label}"
CFG="${3:?a|b}"
command -v python3 >/dev/null || { echo "probe-http-labels.sh needs python3 to mint JWTs" >&2; exit 2; }
E2E="$(cd "$(dirname "$0")" && pwd)"
LOG="$E2E/hl.$LABEL.log"
PROVIDERS="$E2E/.hl.providers.$LABEL.toml"

# -q: an INSERT ... RETURNING would otherwise print its command tag after the id.
q() { PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -X -qtA -c "$1"; }

echo "### binary: $BIN"
LOCKFIFO="$E2E/.hllock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"
PID=""
cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO" "$PROVIDERS"
}
trap cleanup EXIT
echo "### serialized on advisory lock 918273645"

"$E2E/set-config.sh" "$CFG" >/dev/null 2>&1
echo "### $(q "SELECT 'config: ' || CASE WHEN EXISTS(SELECT 1 FROM pg_policy WHERE polname='claims_privacy') THEN 'B (prod-faithful)' ELSE 'A (clean series)' END")"
q "TRUNCATE claims, evidence, edges, reasoning_traces, mass_functions, claim_frames,
           recall_events, challenges, events, workflows, papers CASCADE;" >/dev/null 2>&1
echo "### app role: $(PGCONNECT_TIMEOUT=5 psql "$E2E_APP_DSN" -X -tA -c "SELECT current_user || ' session_user=' || session_user || ' bypass=' || epigraph_bypass()::text" 2>&1 | head -1)"

# ── seed ──
# An agent with its personal group and an admin membership, the shape
# AgentRepository::ensure_personal_group produces. Prints "<agent> <group>".
seed_agent() {
  local a
  a="$(q "INSERT INTO agents (id, public_key, agent_type)
          VALUES (gen_random_uuid(), sha256(gen_random_uuid()::text::bytea), 'system') RETURNING id")"
  local g
  g="$(q "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id)
          VALUES ('hl:$1:$a', 'did:epigraph:personal:$a', ''::bytea, 'personal', '$a') RETURNING id")"
  q "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
     VALUES ('$g', '$a', ''::bytea, 0, 'admin')" >/dev/null
  echo "$a $g"
}
read -r OWNER OWNER_G <<<"$(seed_agent owner)"
read -r ADMIN _ADMIN_G <<<"$(seed_agent admin)"
read -r PEER _PEER_G <<<"$(seed_agent peer)"
read -r STRANGER STRANGER_G <<<"$(seed_agent stranger)"
TEAM_G="$(q "INSERT INTO groups (display_name, did_key, public_key, kind)
             VALUES ('hl team $LABEL', 'did:test:hl:' || gen_random_uuid(), decode(repeat('ab', 32), 'hex'), 'team')
             RETURNING id")"
WORLD_G="$(q "SELECT id FROM groups WHERE kind = 'world' LIMIT 1")"
claim() {  # $1 author, $2 visibility, $3 owner group, $4 tag
  q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, visibility, owner_group_id, labels)
     VALUES (gen_random_uuid(), 'hl $4 $LABEL', sha256(('hl $4 ' || gen_random_uuid())::bytea), 0.6, '$1', true, '$2', '$3', ARRAY[]::text[])
     RETURNING id"
}
C_OWN_PUB="$(claim "$OWNER" public "$OWNER_G" own-public)"
C_OWN_PRIV="$(claim "$OWNER" group "$OWNER_G" own-private)"
C_OTHER_PUB="$(claim "$STRANGER" public "$STRANGER_G" other-public)"
C_FOREIGN_PRIV="$(claim "$STRANGER" group "$TEAM_G" foreign-private)"
C_WORLD_PUB="$(claim "$STRANGER" public "$WORLD_G" world-public)"
for c in "$C_OWN_PUB" "$C_OWN_PRIV" "$C_OTHER_PUB" "$C_FOREIGN_PRIV" "$C_WORLD_PUB"; do
  [ -n "$c" ] || { echo "FAIL: a seed claim was not written"; exit 1; }
done

# ── server ──
SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
: > "$PROVIDERS"
: > "$LOG"
env -u EPIGRAPH_ALLOW_INSECURE_SECRET \
  DATABASE_URL="$E2E_APP_DSN" MAINTENANCE_DATABASE_URL="$E2E_MAINT_DSN" \
  EPIGRAPH_JWT_SECRET="$SECRET" EPIGRAPH_ENV=test EPIGRAPH_DISABLE_JOBS=1 \
  EPIGRAPH_PROVIDERS_CONFIG="$PROVIDERS" EPIGRAPH_PORT="$PORT" EPIGRAPH_METRICS_ADDR=127.0.0.1:0 \
  OPENAI_API_KEY= RUST_LOG=warn "$BIN" >> "$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 60); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/health" && break
  kill -0 "$PID" 2>/dev/null || break
  sleep 1
done
curl -s -o /dev/null "http://127.0.0.1:$PORT/health" || { echo "FAIL: server never answered"; tail -30 "$LOG"; exit 1; }

# HS256 over EpiGraphClaims (crates/epigraph-auth). iat/nbf are backdated: the
# validator's leeway is 0.
mint() {  # $1 agent id, $2 scopes (comma-separated)
  SECRET="$SECRET" python3 - "$1" "$2" <<'PY'
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
T_OWNER="$(mint "$OWNER" claims:read,claims:write)"
T_ADMIN="$(mint "$ADMIN" claims:read,claims:write,claims:admin)"
T_PEER="$(mint "$PEER" claims:read,claims:write)"

# ── probe ──
# One line per case: HTTP status, then whether the label landed on the row.
case_() {  # $1 case name, $2 token, $3 claim
  local tag="hl-$1" status landed
  status="$(curl -s -o "$E2E/.hl.body.$LABEL" -w '%{http_code}' -X PATCH \
    -H "Authorization: Bearer $2" -H 'Content-Type: application/json' \
    "http://127.0.0.1:$PORT/api/v1/claims/$3/labels" -d "{\"add\":[\"$tag\"]}")"
  landed="$(q "SELECT '$tag' = ANY(labels) FROM claims WHERE id = '$3'")"
  printf '%-36s status=%s label_on_row=%s  %s\n' "$1" "$status" "$landed" \
    "$(head -c 140 "$E2E/.hl.body.$LABEL" | tr '\n' ' ')"
}
case_ owner/own-public        "$T_OWNER" "$C_OWN_PUB"
case_ owner/own-private       "$T_OWNER" "$C_OWN_PRIV"
case_ admin/other-public      "$T_ADMIN" "$C_OTHER_PUB"
case_ admin/foreign-private   "$T_ADMIN" "$C_FOREIGN_PRIV"
case_ admin/world-public      "$T_ADMIN" "$C_WORLD_PUB"
case_ peer/other-public       "$T_PEER"  "$C_OTHER_PUB"
rm -f "$E2E/.hl.body.$LABEL"
