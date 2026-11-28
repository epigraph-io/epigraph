#!/usr/bin/env bash
# Check the numbers of the migration files a change ADDS (CI, lint job).
#
#   scripts/ci/check_migration_numbers.sh [<base>]
#
# <base> defaults to `git merge-base HEAD origin/main`. CI passes HEAD^1: on a
# pull request HEAD is the test merge commit, so HEAD^1 is the current tip of
# the target branch, and a number some other change took since this branch
# was cut is caught too.
#
# The head is the highest numeric prefix of migrations/*.sql at <base>. Each
# migrations/*.sql added in <base>..HEAD must:
#   * be named <number>_<name>.sql (sqlx's versioned form);
#   * be numbered ABOVE the head. sqlx applies a file numbered below an
#     already-applied version out of order, and a deployment's head check
#     refuses one; a number below the head is never free by default;
#   * share its number with no other file in migrations/ at HEAD.
# The one exception to "above the head": a number inside a block listed in the
# "Reserved blocks" table of migrations/README.md (a row whose first cell is
# `NNN` or `NNN-MMM`, hyphen or en dash). It must still be unique.
#
# Only added files are read: renames count as additions (--no-renames), and an
# edit to an existing migration is a different rule (migrations are
# append-only; see migrations/README.md). Run from anywhere inside the repository.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
base=${1:-}
if [[ -z $base ]]; then
  base=$(git merge-base HEAD origin/main) || {
    echo "check_migration_numbers: no merge-base with origin/main; pass <base>" >&2
    exit 2
  }
fi
git rev-parse --verify --quiet "$base^{commit}" >/dev/null || {
  echo "check_migration_numbers: base '$base' is not a commit" >&2
  exit 2
}

name_re='^migrations/([0-9]+)_[^/]*\.sql$'

# The numbers of the versioned files in migrations/ at <rev>, one per line.
numbers_at() {
  git ls-tree --name-only "$1" migrations/ | while IFS= read -r f; do
    if [[ $f =~ $name_re ]]; then echo $((10#${BASH_REMATCH[1]})); fi
  done
}

head_num=0
while IFS= read -r n; do
  if ((n > head_num)); then head_num=$n; fi
done < <(numbers_at "$base")
if ((head_num == 0)); then
  # Fail closed: no head means nothing below it could be caught.
  echo "check_migration_numbers: no versioned migrations/*.sql at base $base" >&2
  exit 2
fi

# Reserved blocks: "lo hi" per row of the README's "Reserved blocks" table.
reserved=()
while IFS= read -r line; do
  reserved+=("$line")
done < <(git show HEAD:migrations/README.md 2>/dev/null | awk '
  /^#+[ \t]+Reserved blocks[ \t]*$/ { on = 1; next }
  on && /^#/ { on = 0 }
  on && /^\|/ {
    cell = $0; sub(/^\|[ \t]*/, "", cell); sub(/[ \t]*\|.*$/, "", cell)
    gsub(/`|\*/, "", cell)
    gsub(/–/, "-", cell)
    if (cell ~ /^[0-9]+$/) print cell + 0, cell + 0
    else if (cell ~ /^[0-9]+-[0-9]+$/) { split(cell, r, "-"); print r[1] + 0, r[2] + 0 }
  }')

in_reserved() {
  local n=$1 row lo hi
  for row in ${reserved[@]+"${reserved[@]}"}; do
    read -r lo hi <<<"$row"
    if ((n >= lo && n <= hi)); then return 0; fi
  done
  return 1
}

declare -A count=()
while IFS= read -r n; do
  count[$n]=$((${count[$n]:-0} + 1))
done < <(numbers_at HEAD)

added=0
problems=0
while IFS= read -r f; do
  [[ $f == migrations/*.sql && $f != migrations/*/* ]] || continue
  added=$((added + 1))
  if [[ ! $f =~ $name_re ]]; then
    echo "FAIL $f: not named <number>_<name>.sql"
    problems=$((problems + 1))
    continue
  fi
  n=$((10#${BASH_REMATCH[1]}))
  if ((n <= head_num)) && ! in_reserved "$n"; then
    echo "FAIL $f: number $n is not above the head at the base ($head_num); take $((head_num + 1)) or later"
    problems=$((problems + 1))
  fi
  if ((${count[$n]:-0} > 1)); then
    echo "FAIL $f: number $n is shared by ${count[$n]} files in migrations/"
    problems=$((problems + 1))
  fi
done < <(git diff --name-only --no-renames --diff-filter=A "$base" HEAD -- migrations/)

echo "check_migration_numbers: head at base $head_num, ${#reserved[@]} reserved block(s), $added added file(s), $problems problem(s)"
((problems == 0))
