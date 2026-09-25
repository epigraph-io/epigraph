#!/usr/bin/env bash
# HTTP arm: the claim-writing routes batch H-a stamps, on the real `server`
# binary, as the real least-privilege role, on both schema configurations.
#
#   ./probe-http-writes.sh <epigraph-api server binary> <label> <a|b> [arm ...]
#
# Arms (default: all):
#   supersede   POST /api/v1/claims/:id/supersede
#   deprecate   DELETE /api/v1/workflows/:id on a legacy FLAT workflow claim
#   outcome     POST /api/v1/workflows/:id/outcome on a legacy FLAT workflow claim
#   propagate   POST /api/v1/bp/propagate with apply_updates=true, scalar mode
#   theme       POST /api/v1/themes/create-with-centroid
#
# WHY THIS PROBE EXISTS. Each of these routes answered 2xx on config A while
# writing nothing, or wrote part of what it reported (batch H-a review): the
# writes ran on the raw, unstamped pool and discarded their errors. The
# in-process API tests connect as a superuser, for whom every write is admitted
# whatever the route stamps, so only a server running as a role RLS filters can
# show the difference. Every line prints the HTTP status AND the rows read back
# through the SU DSN afterwards: a 2xx over unchanged rows and an error over
# changed ones are both failures that only the rows reveal.
#
# Callers (JWTs minted here, HS256, with a secret generated per run and never
# written to disk):
#   OWNER  the author of the OWN rows, a writer of its own personal group
#   ADMIN  the same scopes plus claims:admin, a writer of no group but its own
#   PEER   claims:write, neither
# Rows:
#   own-public / own-private   OWNER's, owned by OWNER's personal group
#   other-public               STRANGER's, owned by STRANGER's personal group
#
# --- credentials come from the environment, never from this file -------------
# Required:
#   E2E_SU_DSN   superuser DSN with DDL rights on the throwaway DB.
#   E2E_APP_DSN  the least-privilege application DSN the server connects as.
#                MUST be a role with rolbypassrls=false, or every arm is vacuous.
# Optional:
#   E2E_MAINT_DSN  the server's MAINTENANCE_DATABASE_URL (its job pool refuses a
#                  non-bypassing one). Defaults to E2E_SU_DSN.
#   E2E_HTTP_PORT  port for the server under test. Default 18098.
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
E2E_MAINT_DSN="${E2E_MAINT_DSN:-$E2E_SU_DSN}"
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
e2e_guard_dsn E2E_MAINT_DSN
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
PORT="${E2E_HTTP_PORT:-18098}"
# -----------------------------------------------------------------------------
set -uo pipefail
BIN="${1:?usage: probe-http-writes.sh <server binary> <label> <a|b> [arm ...]}"
LABEL="${2:?label}"
CFG="${3:?a|b}"
shift 3
ARMS="${*:-supersede deprecate outcome propagate theme}"
command -v python3 >/dev/null || { echo "probe-http-writes.sh needs python3 to mint JWTs" >&2; exit 2; }
E2E="$(cd "$(dirname "$0")" && pwd)"
LOG="$E2E/hw.$LABEL.log"
PROVIDERS="$E2E/.hw.providers.$LABEL.toml"
BODY="$E2E/.hw.body.$LABEL"

q() { PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -X -qtA -c "$1"; }
want() { case " $ARMS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

echo "### binary: $BIN"
echo "### arms: $ARMS"
LOCKFIFO="$E2E/.hwlock.$LABEL"
rm -f "$LOCKFIFO"; mkfifo "$LOCKFIFO"
PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -qtA \
  -c "SELECT pg_advisory_lock(918273645);" -f "$LOCKFIFO" >/dev/null 2>&1 &
LOCKPID=$!
exec 9>"$LOCKFIFO"
PID=""
cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  exec 9>&-; wait $LOCKPID 2>/dev/null; rm -f "$LOCKFIFO" "$PROVIDERS" "$BODY"
}
trap cleanup EXIT
echo "### serialized on advisory lock 918273645"

"$E2E/set-config.sh" "$CFG" >/dev/null 2>&1
echo "### $(q "SELECT 'config: ' || CASE WHEN EXISTS(SELECT 1 FROM pg_policy WHERE polname='claims_privacy') THEN 'B (prod-faithful)' ELSE 'A (clean series)' END")"
q "TRUNCATE claims, evidence, edges, reasoning_traces, mass_functions, claim_frames,
           recall_events, challenges, events, workflows, papers, factors,
           behavioral_executions, claim_versions, claim_themes CASCADE;" >/dev/null 2>&1
echo "### app role: $(PGCONNECT_TIMEOUT=5 psql "$E2E_APP_DSN" -X -tA -c "SELECT current_user || ' bypass=' || epigraph_bypass()::text" 2>&1 | head -1)"

# ── seed ──
seed_agent() {  # prints "<agent> <personal group>"
  local a g
  a="$(q "INSERT INTO agents (id, public_key, agent_type)
          VALUES (gen_random_uuid(), sha256(gen_random_uuid()::text::bytea), 'system') RETURNING id")"
  g="$(q "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id)
          VALUES ('hw:$1:$a', 'did:epigraph:personal:$a', ''::bytea, 'personal', '$a') RETURNING id")"
  q "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
     VALUES ('$g', '$a', ''::bytea, 0, 'admin')" >/dev/null
  echo "$a $g"
}
read -r OWNER OWNER_G <<<"$(seed_agent owner)"
read -r ADMIN _ADMIN_G <<<"$(seed_agent admin)"
read -r PEER _PEER_G <<<"$(seed_agent peer)"
read -r STRANGER STRANGER_G <<<"$(seed_agent stranger)"
VEC="('['||array_to_string(array_fill(0.01::float8, ARRAY[1536]),',')||']')::vector"
claim() {  # $1 author, $2 visibility, $3 owner group, $4 tag, [$5 labels literal], [$6 properties json]
  q "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, visibility, owner_group_id, labels, properties, embedding)
     VALUES (gen_random_uuid(), '$4 $LABEL', sha256(('hw $4 ' || gen_random_uuid())::bytea), 0.7, '$1', true, '$2', '$3',
             ${5:-ARRAY[]::text[]}, '${6:-{\}}'::jsonb, $VEC)
     RETURNING id"
}

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
SCOPES="claims:read,claims:write,workflows:read,workflows:write,graph:read,graph:write,edges:read,edges:write"
T_OWNER="$(mint "$OWNER" "$SCOPES")"
T_OWNER_ADMIN="$(mint "$OWNER" "$SCOPES,claims:admin")"
T_ADMIN="$(mint "$ADMIN" "$SCOPES,claims:admin")"
T_PEER="$(mint "$PEER" "$SCOPES")"

# req <method> <path> <token> [json body] -> sets STATUS, body in $BODY
req() {
  if [ -n "${4:-}" ]; then
    STATUS="$(curl -s -o "$BODY" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $3" \
      -H 'Content-Type: application/json' "http://127.0.0.1:$PORT$2" -d "$4")"
  else
    STATUS="$(curl -s -o "$BODY" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $3" \
      "http://127.0.0.1:$PORT$2")"
  fi
}
line() { printf '%-40s status=%s  %s  | %s\n' "$1" "$STATUS" "$2" "$(head -c 130 "$BODY" | tr '\n' ' ')"; }

# ── supersede ──
if want supersede; then
  echo
  echo "=== POST /api/v1/claims/:id/supersede ==="
  sup() {  # $1 case, $2 token, $3 claim
    req POST "/api/v1/claims/$3/supersede" "$2" "{\"content\":\"hw superseding $1 $LABEL\",\"truth_value\":0.6,\"reason\":\"probe\"}"
    line "$1" "old_is_current=$(q "SELECT is_current FROM claims WHERE id='$3'") replacements=$(q "SELECT count(*) FROM claims WHERE supersedes='$3'") versions=$(q "SELECT count(*) FROM claim_versions v JOIN claims c ON c.id = v.claim_id WHERE c.supersedes='$3'")"
  }
  sup owner/own-public   "$T_OWNER" "$(claim "$OWNER" public "$OWNER_G" own-public)"
  sup owner/own-private  "$T_OWNER" "$(claim "$OWNER" group "$OWNER_G" own-private)"
  sup admin/other-public "$T_ADMIN" "$(claim "$STRANGER" public "$STRANGER_G" other-public)"
  sup peer/other-public  "$T_PEER"  "$(claim "$STRANGER" public "$STRANGER_G" other-public-2)"
fi

# ── deprecate_workflow ──
if want deprecate; then
  echo
  echo "=== DELETE /api/v1/workflows/:id (legacy flat workflow claim) ==="
  dep() {  # $1 case, $2 token, $3 claim
    req DELETE "/api/v1/workflows/$3?reason=probe" "$2"
    line "$1" "is_current=$(q "SELECT is_current FROM claims WHERE id='$3'") truth=$(q "SELECT truth_value FROM claims WHERE id='$3'")"
  }
  dep owner/own-flat-public  "$T_OWNER" "$(claim "$OWNER" public "$OWNER_G" own-flat-pub "ARRAY['workflow']::text[]")"
  dep owner/own-flat-private "$T_OWNER" "$(claim "$OWNER" group "$OWNER_G" own-flat-priv "ARRAY['workflow']::text[]")"
  dep peer/other-flat-public "$T_PEER"  "$(claim "$STRANGER" public "$STRANGER_G" other-flat-pub "ARRAY['workflow']::text[]")"
fi

# ── report_outcome ──
if want outcome; then
  echo
  echo "=== POST /api/v1/workflows/:id/outcome (legacy flat workflow claim) ==="
  out() {  # $1 case, $2 token, $3 claim
    req POST "/api/v1/workflows/$3/outcome" "$2" '{"success":true,"quality":0.9,"outcome_details":"probe"}'
    line "$1" "truth=$(q "SELECT round(truth_value::numeric,4) FROM claims WHERE id='$3'") use_count=$(q "SELECT coalesce(properties->>'use_count','-') FROM claims WHERE id='$3'") executions=$(q "SELECT count(*) FROM behavioral_executions WHERE workflow_id='$3'")"
  }
  out owner/own-flat-public  "$T_OWNER" "$(claim "$OWNER" public "$OWNER_G" out-flat-pub "ARRAY['workflow']::text[]" '{"goal":"probe goal"}')"
  out owner/own-flat-private "$T_OWNER" "$(claim "$OWNER" group "$OWNER_G" out-flat-priv "ARRAY['workflow']::text[]" '{"goal":"probe goal"}')"
  out peer/other-flat-public "$T_PEER"  "$(claim "$STRANGER" public "$STRANGER_G" out-other-pub "ARRAY['workflow']::text[]" '{"goal":"probe goal"}')"
fi

# ── bp/propagate ──
if want propagate; then
  echo
  echo "=== POST /api/v1/bp/propagate apply_updates=true, scalar mode ==="
  q "DELETE FROM factors" >/dev/null
  P1="$(claim "$OWNER" public "$OWNER_G" bp-own-1)"
  P2="$(claim "$OWNER" public "$OWNER_G" bp-own-2)"
  q "UPDATE claims SET pignistic_prob = 0.9 WHERE id = '$P1'; UPDATE claims SET pignistic_prob = 0.2 WHERE id = '$P2'" >/dev/null
  q "INSERT INTO factors (factor_type, variable_ids, potential) VALUES ('evidential_support', ARRAY['$P1','$P2']::uuid[], '{\"strength\":0.9}')" >/dev/null
  bp() {  # $1 case, $2 token, $3 claim to watch
    local before; before="$(q "SELECT round(pignistic_prob::numeric,4) FROM claims WHERE id='$3'")"
    req POST "/api/v1/bp/propagate" "$2" '{"apply_updates":true,"mode":"scalar"}'
    line "$1" "applied=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('applied'))" "$BODY" 2>/dev/null) listed=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1])).get('updated_beliefs') or []))" "$BODY" 2>/dev/null) betp=$before->$(q "SELECT round(pignistic_prob::numeric,4) FROM claims WHERE id='$3'")"
  }
  bp owner/own-factor "$T_OWNER" "$P2"
  # A second factor into a STRANGER's claim: the owner cannot write it.
  S1="$(claim "$STRANGER" public "$STRANGER_G" bp-stranger)"
  q "UPDATE claims SET pignistic_prob = 0.9 WHERE id = '$P1'; UPDATE claims SET pignistic_prob = 0.2 WHERE id IN ('$P2', '$S1')" >/dev/null
  q "INSERT INTO factors (factor_type, variable_ids, potential) VALUES ('evidential_support', ARRAY['$P1','$S1']::uuid[], '{\"strength\":0.9}')" >/dev/null
  bp owner/own+stranger-factor "$T_OWNER" "$P2"
  echo "   (stranger claim betp after: $(q "SELECT round(pignistic_prob::numeric,4) FROM claims WHERE id='$S1'"))"
fi

# ── themes/create-with-centroid ──
if want theme; then
  echo
  echo "=== POST /api/v1/themes/create-with-centroid (claims:admin) ==="
  th() {  # $1 case, $2 token, $3 claim a, $4 claim b
    local before; before="$(q "SELECT count(*) FROM claim_themes")"
    req POST "/api/v1/themes/create-with-centroid" "$2" "{\"label\":\"hw-$1-$LABEL\",\"description\":\"probe\",\"claim_ids\":[\"$3\",\"$4\"]}"
    line "$1" "claim_themes=$before->$(q "SELECT count(*) FROM claim_themes") themed=$(q "SELECT count(*) FROM claims WHERE id IN ('$3','$4') AND theme_id IS NOT NULL")"
  }
  th owner-admin/own-claims   "$T_OWNER_ADMIN" "$(claim "$OWNER" public "$OWNER_G" th-own-1)" "$(claim "$OWNER" public "$OWNER_G" th-own-2)"
  th owner-admin/other-claims "$T_OWNER_ADMIN" "$(claim "$STRANGER" public "$STRANGER_G" th-other-1)" "$(claim "$STRANGER" public "$STRANGER_G" th-other-2)"
fi

echo
echo "=== server log: errors ==="
grep -ciE '"level":"ERROR"| ERROR ' "$LOG" | sed 's/^/error lines: /'
