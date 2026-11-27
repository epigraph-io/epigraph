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

# The parsers (e2e_dsn_port, e2e_dsn_host) and the refusal rule (e2e_guard_dsn)
# live in dsn-lib.sh, which scripts/e2e/test-dsn-guard.sh tests. BASH_SOURCE,
# not $0: $0 is the script that sourced this file.
# shellcheck source=dsn-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dsn-lib.sh"

e2e_guard_dsn E2E_SU_DSN
e2e_guard_dsn E2E_APP_DSN
E2E_SU_PORT="$(e2e_dsn_port "$E2E_SU_DSN")"
export E2E_SU_PORT
E2E_SU_HOST="$(e2e_dsn_host "$E2E_SU_DSN")"
export E2E_SU_HOST
