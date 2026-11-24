#!/usr/bin/env bash
# with_test_api.sh: run a command against a live epigraph-api serving a
# disposable test database, with a bearer token for it.
#
#   TEST_API_DATABASE_URL=postgres://.../epigraph_py_test \
#     tests/ci/with_test_api.sh <command...>
#
# Starts the `server` binary (TEST_API_BIN, default target/debug/server) on
# $TEST_API_PORT (default: a free port picked at runtime, so two runs on one
# host never share a listener) against TEST_API_DATABASE_URL, whose
# database name must end in `_test`. It inserts two agent rows, mints an HS256
# JWT for each with a per-run secret that is never written to disk, and runs
# the command with
#   DEDUP_TEST_API_BASE        http://127.0.0.1:$TEST_API_PORT
#   DEDUP_TEST_TOKEN           claims:read, claims:write and claims:admin
#   DEDUP_TEST_WRITER_TOKEN    claims:read and claims:write only (no admin)
#   DEDUP_TEST_WRITER_AGENT    the writer token's agent id
#   DEDUP_TEST_WRITER_GROUP    that agent's personal group, which it is admin of
# exported (tests/dedup/test_fuzzy_dedup_retraction.py reads them). The admin
# token marks claims another agent seeded; the writer token is the common case,
# an author marking a duplicate of its own claim in a group it writes, which the
# dedup endpoint admits on its author arm without claims:admin (backlog
# 32905f60).
# The server is stopped by its recorded PID when the command exits, so it never
# outlives the step. Exit code: the command's, or 1 when the server does not
# come up.
#
# Used by the `python` job in .github/workflows/ci.yml (backlog 03fd7e00).
# Needs python3 with psycopg2, and curl.
set -uo pipefail

: "${TEST_API_DATABASE_URL:?set TEST_API_DATABASE_URL (the migrated _test database the API serves)}"
[ $# -gt 0 ] || { echo "usage: with_test_api.sh <command...>" >&2; exit 64; }
case "${TEST_API_DATABASE_URL%%\?*}" in
  *_test) ;;
  *) echo "with_test_api.sh: refusing a database whose name does not end in _test" >&2; exit 64 ;;
esac

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${TEST_API_BIN:-$ROOT/target/debug/server}"
if [ -n "${TEST_API_PORT:-}" ]; then
  PORT="$TEST_API_PORT"
else
  PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
fi
[ -x "$BIN" ] || { echo "with_test_api.sh: no server binary at $BIN (cargo build -p epigraph-api --bin server)" >&2; exit 1; }
# Refuse a port something already answers on: /health from another run's
# server (different JWT secret) would otherwise pass the readiness check below.
if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/health"; then
  echo "with_test_api.sh: port $PORT already answers /health; refusing to share another server" >&2
  exit 1
fi

WORK="$(mktemp -d)"
PID=""
cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# An empty providers file: without EPIGRAPH_PROVIDERS_CONFIG the server reads
# the checkout's providers.toml, which is gitignored and absent in CI.
: > "$WORK/providers.toml"
SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# MAINTENANCE_DATABASE_URL is unset because the server refuses to start with
# it. EPIGRAPH_ALLOW_INSECURE_SECRET is unset so the boot-time secret gate runs
# and admits the per-run 32-byte secret on its merits.
env -u MAINTENANCE_DATABASE_URL -u EPIGRAPH_ALLOW_INSECURE_SECRET \
  DATABASE_URL="$TEST_API_DATABASE_URL" \
  EPIGRAPH_JWT_SECRET="$SECRET" EPIGRAPH_ENV=test \
  EPIGRAPH_PROVIDERS_CONFIG="$WORK/providers.toml" \
  EPIGRAPH_PORT="$PORT" EPIGRAPH_METRICS_ADDR=127.0.0.1:0 \
  OPENAI_API_KEY= RUST_LOG="${TEST_API_RUST_LOG:-warn}" \
  "$BIN" > "$WORK/server.log" 2>&1 &
PID=$!

up=0
for _ in $(seq 1 90); do
  kill -0 "$PID" 2>/dev/null || break
  # Ready only when /health answers AND the server we started is still alive:
  # a listener that is not ours must never count as up.
  if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/health" && kill -0 "$PID" 2>/dev/null; then
    up=1; break
  fi
  sleep 1
done
if [ "$up" != 1 ]; then
  echo "with_test_api.sh: the API we started (pid $PID) never answered /health on port $PORT; server log tail:" >&2
  tail -40 "$WORK/server.log" >&2
  exit 1
fi

# One agent row per token principal (the test fixtures' shape: a real 32-byte
# key satisfies agents_public_key_length), the writer's personal group with its
# admin membership, then the tokens, with the claim set
# scripts/e2e/probe-http-writes.sh mints. Printed one per line: admin token,
# writer token, writer agent, writer group.
MINTED="$(SECRET="$SECRET" python3 - <<'PY'
import base64, hashlib, hmac, json, os, time, uuid
import psycopg2

admin, writer = str(uuid.uuid4()), str(uuid.uuid4())
conn = psycopg2.connect(os.environ["TEST_API_DATABASE_URL"])
with conn, conn.cursor() as cur:
    for agent in (admin, writer):
        cur.execute(
            "INSERT INTO agents (id, public_key, role, state) "
            "VALUES (%s::uuid, %s, 'researcher', 'active')",
            (agent, psycopg2.Binary(os.urandom(32))),
        )
    cur.execute(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) "
        "VALUES (%s, 'did:epigraph:personal:' || %s, ''::bytea, 'personal', %s) "
        "RETURNING id::text",
        (f"dedup-writer:{writer}", writer, writer),
    )
    group = cur.fetchone()[0]
    cur.execute(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) "
        "VALUES (%s, %s, ''::bytea, 0, 'admin')",
        (group, writer),
    )
conn.close()

b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
now = int(time.time()) - 2


def mint(agent, scopes):
    claims = {"sub": agent, "iss": "epigraph", "aud": "epigraph-api", "exp": now + 3600,
              "iat": now, "nbf": now, "jti": str(uuid.uuid4()), "scopes": scopes,
              "client_type": "service", "owner_id": agent, "agent_id": agent}
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = hmac.new(os.environ["SECRET"].encode(), f"{head}.{body}".encode(),
                   hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


print(mint(admin, ["claims:read", "claims:write", "claims:admin"]))
print(mint(writer, ["claims:read", "claims:write"]))
print(writer)
print(group)
PY
)" || { echo "with_test_api.sh: could not seed the agents or mint the tokens" >&2; exit 1; }
{ read -r TOKEN; read -r WRITER_TOKEN; read -r WRITER_AGENT; read -r WRITER_GROUP; } <<< "$MINTED"
[ -n "$WRITER_GROUP" ] || { echo "with_test_api.sh: the mint printed fewer than four lines" >&2; exit 1; }

DEDUP_TEST_API_BASE="http://127.0.0.1:$PORT" DEDUP_TEST_TOKEN="$TOKEN" \
  DEDUP_TEST_WRITER_TOKEN="$WRITER_TOKEN" DEDUP_TEST_WRITER_AGENT="$WRITER_AGENT" \
  DEDUP_TEST_WRITER_GROUP="$WRITER_GROUP" "$@"
rc=$?
if [ "$rc" != 0 ]; then
  echo "with_test_api.sh: command exited $rc; server log tail:" >&2
  tail -40 "$WORK/server.log" >&2
fi
exit "$rc"
