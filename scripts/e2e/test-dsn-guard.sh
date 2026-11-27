#!/usr/bin/env bash
# Self-test for the e2e harness's DSN guard (scripts/e2e/dsn-lib.sh, run by
# dsn-guard.sh). No database, no network: it only parses synthetic DSNs.
#
# Asserts that:
#   1. e2e_dsn_host / e2e_dsn_port read the host and port the DSN names: a DNS
#      name, a bracketed IPv6 literal (brackets stripped) and the unix-socket
#      form (`?host=/dir&port=N`, empty authority);
#   2. e2e_guard_dsn accepts a DSN naming a host and a non-5432 port, and
#      refuses (exit 2, with the reason) one with no host, no port, or port
#      5432, the production cluster's;
#   3. dsn-guard.sh itself, sourced as the e2e scripts source it, exports the
#      superuser DSN's host and port, and stops a script on a refused DSN.
# A regression to a hard-coded loopback host (the defect behind backlog
# 8a0a09d8) fails case 1.
#
# Usage: scripts/e2e/test-dsn-guard.sh
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=dsn-lib.sh
. "$here/dsn-lib.sh"
failures=0

pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; failures=$((failures + 1)); }

# eq <name> <want> <got>
eq() {
  if [[ $3 == "$2" ]]; then pass "$1"; else fail "$1: want '$2', got '$3'"; fi
}

# guard <name> <dsn> <want rc> <stderr fragment|->: runs e2e_guard_dsn on a
# variable holding <dsn> in a subshell (the guard calls `exit`).
guard() {
  local name=$1 dsn=$2 want=$3 frag=$4 rc=0 err
  err=$(TEST_DSN="$dsn" bash -c '. "$1/dsn-lib.sh"; e2e_guard_dsn TEST_DSN' _ "$here" 2>&1) || rc=$?
  if [[ $rc != "$want" ]]; then
    fail "$name: want rc=$want, got rc=$rc"; sed 's/^/       | /' <<<"$err"; return
  fi
  if [[ $frag == - ]]; then
    if [[ -n $err ]]; then fail "$name: unexpected output"; sed 's/^/       | /' <<<"$err"; return; fi
  elif ! grep -qF -- "$frag" <<<"$err"; then
    fail "$name: reason '$frag' not given"; sed 's/^/       | /' <<<"$err"; return
  fi
  pass "$name"
}

# --- 1. parsing ---------------------------------------------------------------
eq "host of a DNS-name DSN"   db.internal     "$(e2e_dsn_host 'postgres://u:p@db.internal:5433/x')"
eq "port of a DNS-name DSN"   5433            "$(e2e_dsn_port 'postgres://u:p@db.internal:5433/x')"
eq "host of a DSN with no credentials" db.internal "$(e2e_dsn_host 'postgresql://db.internal:5433/x')"
eq "host of an IPv6 DSN"      ::1             "$(e2e_dsn_host 'postgres://u:p@[::1]:5433/x')"
eq "port of an IPv6 DSN"      5433            "$(e2e_dsn_port 'postgres://u:p@[::1]:5433/x')"
eq "host of a unix-socket DSN" /run/postgresql "$(e2e_dsn_host 'postgres:///x?host=/run/postgresql&port=5433')"
eq "port of a unix-socket DSN" 5433           "$(e2e_dsn_port 'postgres:///x?host=/run/postgresql&port=5433')"
eq "no host when none is named" ""            "$(e2e_dsn_host 'postgres:///x?port=5433')"
eq "no port when none is named" ""            "$(e2e_dsn_port 'postgres://u:p@db.internal/x')"

# --- 2. the refusal rule -----------------------------------------------------------
guard "accepts a host and a test port"     'postgres://u:p@db.internal:5433/x'             0 -
guard "accepts the unix-socket form"       'postgres:///x?host=/run/postgresql&port=5433'  0 -
guard "refuses a DSN with no host"         'postgres:///x?port=5433'                       2 "names no host"
guard "refuses a DSN with no port"         'postgres://u:p@db.internal/x'                  2 "names no explicit port"
guard "refuses port 5432"                  'postgres://u:p@db.internal:5432/x'             2 "port 5432"
guard "refuses port 5432 by query param"   'postgres:///x?host=/run/postgresql&port=5432'  2 "port 5432"

# --- 3. dsn-guard.sh as the e2e scripts source it ------------------------------------
rc=0
out=$(E2E_SU_DSN='postgres://su:pw@db.internal:5433/x' E2E_APP_DSN='postgres://app:pw@db.internal:5433/x' \
  bash -c '. "$1/dsn-guard.sh"; echo "$E2E_SU_HOST $E2E_SU_PORT"' _ "$here" 2>&1) || rc=$?
eq "dsn-guard.sh exports the superuser host and port" "0 db.internal 5433" "$rc $out"

rc=0
out=$(E2E_SU_DSN='postgres://su:pw@db.internal:5433/x' E2E_APP_DSN='postgres://app:pw@db.internal:5432/x' \
  bash -c '. "$1/dsn-guard.sh"; echo reached' _ "$here" 2>&1) || rc=$?
if [[ $rc == 2 ]] && ! grep -q reached <<<"$out"; then pass "dsn-guard.sh stops the script on an app DSN on 5432"
else fail "dsn-guard.sh stops the script on an app DSN on 5432 (rc=$rc)"; sed 's/^/       | /' <<<"$out"; fi

if ((failures)); then
  echo "test-dsn-guard: $failures case(s) failed" >&2
  exit 1
fi
echo "test-dsn-guard: all cases passed"
