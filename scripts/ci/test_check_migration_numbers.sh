#!/usr/bin/env bash
# Fixture test for scripts/ci/check_migration_numbers.sh.
#
# Builds throwaway git repositories (nothing outside a temp directory is
# touched) whose base holds migrations 001, 008 and 012, adds files on top, and
# asserts the check's verdict:
#   * the next number (013) and a gap above the head (020) pass; leading zeros
#     are read as decimal (008 and 012 are not octal);
#   * a number below the head fails, and so does the head's own number;
#   * two added files with one number fail, as does a name sqlx cannot version;
#   * a number below the head inside a README "Reserved blocks" row passes,
#     unless another file shares it; a RESERVED range mentioned elsewhere in the
#     README is not an allowance;
#   * renames count as additions; a change adding no migration passes; a base
#     with no versioned migration is refused (exit 2) rather than passed;
#   * with no argument the base is the merge-base with origin/main.
#
# Usage: scripts/ci/test_check_migration_numbers.sh
set -euo pipefail

check=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check_migration_numbers.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
n=0

g() { git -C "$r" -c user.name=ci -c user.email=ci@example.invalid "$@"; }

# fixture <readme text>: a fresh repository with the base migrations and the
# README committed; sets $r and $base.
fixture() {
  n=$((n + 1))
  r=$work/repo$n
  git init -q -b main "$r"
  mkdir -p "$r/migrations"
  for f in 001_init.sql 008_eight.sql 012_twelve.sql; do echo "-- $f" >"$r/migrations/$f"; done
  printf '%s\n' "$1" >"$r/migrations/README.md"
  g add -A && g commit -q -m base
  base=$(g rev-parse HEAD)
}

# add <file>...: commit new files under migrations/ on top of the base.
add() {
  local f
  for f in "$@"; do echo "-- $f" >"$r/migrations/$f"; done
  g add -A && g commit -q -m change
}

# expect <name> <want rc> <fragment|-> [<base arg>]: runs the check in $r.
expect() {
  local name=$1 want=$2 frag=$3 rc=0 out
  out=$(cd "$r" && "$check" ${4+"$4"} 2>&1) || rc=$?
  if [[ $rc != "$want" ]]; then
    echo "FAIL - $name: want rc=$want, got rc=$rc"; sed 's/^/       | /' <<<"$out"; failures=$((failures + 1)); return
  fi
  if [[ $frag != - ]] && ! grep -qF -- "$frag" <<<"$out"; then
    echo "FAIL - $name: '$frag' not reported"; sed 's/^/       | /' <<<"$out"; failures=$((failures + 1)); return
  fi
  echo "ok   - $name"
}

plain_readme='# Migrations

- **005-009**: RESERVED for an old series (prose, not the table).'
reserved_readme='# Migrations

## Reserved blocks

| Block | Holder |
|-------|--------|
| `009`–`010` | a fixture series |
| 005 | a single slot |

## Next section

| 002 | not a reserved row (other section) |'

fixture "$plain_readme"; add 013_next.sql
expect "head+1 passes"                     0 "head at base 12" "$base"
fixture "$plain_readme"; add 020_gap.sql
expect "a gap above the head passes"       0 - "$base"
fixture "$plain_readme"; add 009_below.sql
expect "below the head fails"              1 "number 9 is not above the head at the base (12)" "$base"
fixture "$plain_readme"; add 012_same.sql
expect "the head's own number fails"       1 "number 12 is shared by 2 files" "$base"
fixture "$plain_readme"; add 013_a.sql 013_b.sql
expect "a duplicated new number fails"     1 "number 13 is shared by 2 files" "$base"
fixture "$plain_readme"; add 013_a.sql 0013_b.sql
expect "a duplicate behind leading zeros fails" 1 "number 13 is shared by 2 files" "$base"
fixture "$plain_readme"; add 13-bad-name.sql
expect "an unversioned name fails"         1 "not named <number>_<name>.sql" "$base"
fixture "$plain_readme"; add 007_prose.sql
expect "a RESERVED range in prose is no allowance" 1 "number 7 is not above the head" "$base"
fixture "$reserved_readme"; add 009_held.sql
expect "a number in a reserved block passes" 0 "2 reserved block(s)" "$base"
fixture "$reserved_readme"; add 005_single.sql
expect "a single reserved slot passes"     0 - "$base"
fixture "$reserved_readme"; add 002_other.sql
expect "a row outside the table's section is not reserved" 1 "number 2 is not above the head" "$base"
fixture "$reserved_readme"; add 010_a.sql 010_b.sql
expect "a reserved number must still be unique" 1 "number 10 is shared by 2 files" "$base"
fixture "$plain_readme"; g mv migrations/008_eight.sql migrations/013_eight.sql; g commit -q -m rename
expect "a rename into a new number is checked as an addition" 0 "1 added file(s)" "$base"
fixture "$plain_readme"; g mv migrations/012_twelve.sql migrations/011_twelve.sql; g commit -q -m rename
expect "a rename below the head fails"     1 "number 11 is not above the head" "$base"
fixture "$plain_readme"; echo "-- edit" >>"$r/migrations/012_twelve.sql"; g commit -q -am edit
expect "a change adding no migration passes" 0 "0 added file(s)" "$base"
fixture "$plain_readme"; mkdir -p "$r/migrations/sub"; add sub/003_nested.sql
expect "a file in a subdirectory is not a migration" 0 "0 added file(s)" "$base"

# A base with no versioned migration has no head to check against: refuse.
fixture "$plain_readme"; g rm -q migrations/0*.sql; g commit -q -m empty; base=$(g rev-parse HEAD); add 001_x.sql
expect "a base with no migrations is refused" 2 "no versioned migrations" "$base"

# Default base: the merge-base with origin/main, here the base commit, even
# after origin/main moved on with a migration of its own.
fixture "$plain_readme"
g checkout -q -b topic
add 013_topic.sql
g checkout -q main
add 013_main.sql
g update-ref refs/remotes/origin/main main
g checkout -q topic
expect "the default base is the merge-base with origin/main" 0 "head at base 12"
# Against main's tip (what CI's HEAD^1 is on the merge ref), 013 is taken.
g merge -q --no-edit main >/dev/null
expect "a number taken on main since the branch point fails against main's tip" 1 "number 13 is shared by 2 files" "refs/remotes/origin/main"

if ((failures)); then
  echo "test_check_migration_numbers: $failures case(s) failed" >&2
  exit 1
fi
echo "test_check_migration_numbers: all cases passed"
