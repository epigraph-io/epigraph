# Sourced (never executed) by dsn-guard.sh and by test-dsn-guard.sh: the DSN
# parsers and the refusal rule, with no side effect when sourced. dsn-guard.sh
# explains why they exist; it is the file the e2e scripts source, and it runs
# the guard. Keeping the definitions here lets the test exercise them without
# running the guard on the test's own environment, and without a flag that
# could switch the guard off in a real run.

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
