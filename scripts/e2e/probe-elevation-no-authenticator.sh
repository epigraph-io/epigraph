#!/usr/bin/env bash
# The elevation ceremony with NO AUTHENTICATOR fails closed (elevation plan
# EL-14; DESIGN §10 check 7). The in-repo suites drive the ceremony with an
# independent software authenticator over HTTP and pin the protocol-level
# refusals (no assertion, a garbage assertion, another person's passkey); what
# they cannot reach is the PAGE in a real browser that has no passkey to offer.
#
#   ./probe-elevation-no-authenticator.sh <API base URL> <ticket id>
#
# PRECONDITIONS (the operator's, before running):
#   * an `epigraph-api` `server` binary at <API base URL>, on the throwaway
#     database E2E_SU_DSN names, configured with a relying party whose origin
#     is <API base URL> (`EPIGRAPH_WEBAUTHN_RP_ID` / `EPIGRAPH_WEBAUTHN_ORIGIN`;
#     `localhost` is a valid RP id for a browser on the same host);
#   * a LIVE, unasserted ticket <ticket id> of a custodian holding a passkey
#     (`POST /api/v1/elevation/tickets` with that person's token). The passkey
#     is what the page will ask for; the browser here holds none.
#
# ARMS (each prints PASS or FAIL):
#   NOAUTH-EMPTY  a virtual authenticator with no credential: the page says
#                 "Not elevated:", sends nothing to /assert, and the ticket
#                 stays unasserted with no session.
#   NOAUTH-NONE   no authenticator at all: the same.
#
# Measured: NOT YET RUN against a deployed build (this commit adds the probe).
# Needs node + the `playwright` package with Chromium, and psql.

# --- credentials come from the environment, never from this file -------------
: "${E2E_SU_DSN:?set E2E_SU_DSN (superuser DSN for the throwaway e2e database)}"
: "${E2E_APP_DSN:?set E2E_APP_DSN (least-privilege app DSN; rolbypassrls MUST be false)}"
# shellcheck source=dsn-guard.sh
. "$(cd "$(dirname "$0")" && pwd)/dsn-guard.sh"
E2E_SU_PW="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://[^:]+:([^@]*)@.*#\1#')"
E2E_SU_USER="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*://([^:]+):.*#\1#')"
E2E_DB="$(printf '%s' "$E2E_SU_DSN" | sed -E 's#.*/([^/?]+)$#\1#')"
# -----------------------------------------------------------------------------
set -uo pipefail
BASE="${1:?usage: probe-elevation-no-authenticator.sh <API base URL> <ticket id>}"
TICKET="${2:?ticket id}"
E2E="$(cd "$(dirname "$0")" && pwd)"

if ! printf '%s' "$TICKET" | grep -Eq '^[0-9a-fA-F-]{36}$'; then
  echo "ticket id is not a uuid: $TICKET" >&2
  exit 2
fi

q() { PGPASSWORD="$E2E_SU_PW" psql -h "$E2E_SU_HOST" -p "$E2E_SU_PORT" -U "$E2E_SU_USER" -d "$E2E_DB" -tA -c "$1"; }

# The ticket's state: "<outcome or empty>|<asserted>|<session or empty>".
state() {
  q "SELECT coalesce(outcome, ''), (asserted_at IS NOT NULL), coalesce(session_id::text, '') \
       FROM elevation_tickets WHERE id = '$TICKET'"
}

before="$(state)"
if [ "$before" != "|f|" ]; then
  echo "CALIBRATION FAIL: ticket $TICKET is not live and unasserted ($before)"
  exit 1
fi

rc_all=0
for arm in empty none; do
  out="$(node "$E2E/elevation-no-authenticator.mjs" "$BASE/elevate/$TICKET" "$arm")"
  rc=$?
  after="$(state)"
  label="NOAUTH-$(printf '%s' "$arm" | tr '[:lower:]' '[:upper:]')"
  if [ "$rc" -eq 0 ] && [ "$after" = "|f|" ]; then
    echo "$label PASS $out ticket=($after)"
  else
    echo "$label FAIL rc=$rc $out ticket=($after)"
    rc_all=1
  fi
done
exit "$rc_all"
