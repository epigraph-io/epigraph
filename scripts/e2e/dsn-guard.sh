# Sourced (never executed) by every e2e script, right after its
# `: "${E2E_SU_DSN:?…}"` / `: "${E2E_APP_DSN:?…}"` checks and BEFORE any psql or
# server start. Nothing here contains a credential.
#
# WHY IT EXISTS. The scripts parse the user, password and database out of
# E2E_SU_DSN and then run `psql -h HOST -p PORT -U … -d …`. Before this guard they
# passed no `-p`, so the port in the DSN was silently ignored and the
# superuser half of the harness (migrations, policy replay, TRUNCATE) went to
# libpq's default port: 5432, which on the reference host is the PRODUCTION
# cluster. The test cluster is 5433. A caller who did not also export
# PGPORT=5433 got a superuser TRUNCATE aimed at production's port.
#
# WHAT IT DOES:
#   * refuses (exit 2) unless E2E_SU_DSN and E2E_APP_DSN each name an explicit
#     port (the app DSN too: the server binary's driver also defaults to 5432);
#   * refuses (exit 2) when either is on port 5432;
#   * exports E2E_SU_PORT, which every psql call in this directory passes as
#     `-p "$E2E_SU_PORT"`, so the port in the DSN is the port that is used;
#   * exports E2E_SU_HOST, which every psql call passes as `-h "$E2E_SU_HOST"`,
#     so the HOST in the DSN is the host that is used too.
#
# A DSN without a port is refused rather than defaulted, because the default
# is the production port.
#
# THE HOST HALF (backlog 8a0a09d8). The port was honoured from c8cf9323 on, but
# every psql call still hard-coded `-h 127.0.0.1`. A DSN naming another host (a
# container network, a CI service host) therefore ran the harness's SQL checks
# — the TRUNCATE, the policy replay and the row counts that ARE the verdict —
# against whatever listened on loopback, while the server binary (which is
# handed the DSN itself) wrote to the host the DSN named. The verdict then
# described a different database from the one the tools wrote to. A DSN with no
# host is refused for the same reason a DSN with no port is: libpq's default
# is a guess, and a guess is how the port bug happened.

# The port in `scheme://[user[:pw]@]host:PORT/db` (host may be a bracketed IPv6
# literal, `[::1]`), or else a `port=` query parameter (the unix-socket form,
# `…/db?host=/run/postgresql&port=5433`). Prints nothing when neither is present.
e2e_dsn_port() {
  local p
  p="$(printf '%s' "$1" | sed -nE 's#^[A-Za-z][A-Za-z0-9+.-]*://([^@/]*@)?(\[[^]/]*\]|[^/:@?]+):([0-9]+)([/?].*)?$#\3#p')"
  if [ -z "$p" ]; then
    p="$(printf '%s' "$1" | sed -nE 's#.*[?&]port=([0-9]+).*#\1#p')"
  fi
  printf '%s' "$p"
}

# The host in `scheme://[user[:pw]@]HOST[:port]/db`, or else a `host=` query
# parameter (the unix-socket form, `postgres:///db?host=/run/postgresql&port=5433`,
# whose authority is empty). IPv6 brackets are stripped: psql's `-h` takes the
# bare address. Prints nothing when neither form names a host.
e2e_dsn_host() {
  local h
  h="$(printf '%s' "$1" | sed -nE 's#^[A-Za-z][A-Za-z0-9+.-]*://([^@/]*@)?(\[[^]/]*\]|[^/:@?]+)(:[0-9]+)?([/?].*)?$#\2#p')"
  if [ -z "$h" ]; then
    h="$(printf '%s' "$1" | sed -nE 's#.*[?&]host=([^&]+).*#\1#p')"
  fi
  h="${h#[}"; h="${h%]}"
  printf '%s' "$h"
}

e2e_guard_dsn() {
  local name="$1" dsn port
  dsn="${!name:-}"
  if [ -z "$dsn" ]; then
    return 0
  fi
  port="$(e2e_dsn_port "$dsn")"
  if [ -z "$port" ]; then
    echo "$0: refusing: $name names no explicit port. Name the test cluster's port (e.g. :5433); the libpq default, 5432, is the production cluster." >&2
    exit 2
  fi
  if [ "$port" = "5432" ]; then
    echo "$0: refusing: $name is on port 5432, the production cluster. The e2e harness runs only against the test cluster (e.g. :5433)." >&2
    exit 2
  fi
  if [ -z "$(e2e_dsn_host "$dsn")" ]; then
    echo "$0: refusing: $name names no host. Name the test cluster's host explicitly (e.g. 127.0.0.1, or ?host=/path for a unix socket); the harness passes it to every psql call, and defaulting it is how the verdict ends up describing a different database." >&2
    exit 2
  fi
}

e2e_guard_dsn E2E_SU_DSN
e2e_guard_dsn E2E_APP_DSN
E2E_SU_PORT="$(e2e_dsn_port "$E2E_SU_DSN")"
export E2E_SU_PORT
E2E_SU_HOST="$(e2e_dsn_host "$E2E_SU_DSN")"
export E2E_SU_HOST
