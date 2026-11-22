#!/usr/bin/env bash
# Install the sensitive-data hooks (pre-commit and pre-merge-commit) into this
# clone's own hooks directory. See scripts/README.md, "check_sensitive.py".
#
# Run it once per clone, from a checkout you trust (main):
#
#   bash scripts/install-sensitive-hooks.sh
#
# Why not `git config core.hooksPath .githooks`: git then runs whatever
# .githooks/ the CHECKED-OUT branch holds, and those hooks ran whatever
# scripts/check_sensitive.py that branch holds. Checking out a contributor's
# branch to review it and then committing or merging there executed the
# branch's code with your privileges, before anyone had reviewed it.
#
# The hooks this script writes live outside the working tree, so no branch can
# change them, and they run scripts/check_sensitive.py from the blob at a
# TRUSTED ref (default origin/main; override with
# `git config epigraph.sensitiveHookRef <ref>`), never from the working tree.
# A missing ref or blob blocks the commit (exit 2) rather than skipping the
# check. Re-running the script is safe; it never overwrites a hook it did not
# write.
set -euo pipefail

MARK="# installed by scripts/install-sensitive-hooks.sh"
say() { printf 'install-sensitive-hooks: %s\n' "$*" >&2; }
# Canonical absolute path (python3 is already a requirement of the hooks;
# `realpath -m` is GNU-only).
canon() { python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"; }

git rev-parse --git-dir >/dev/null
hooks="$(git rev-parse --path-format=absolute --git-common-dir)/hooks"
top="$(git rev-parse --show-toplevel)"

# core.hooksPath in this repository's config replaces the hooks directory. Keep
# it only when it already names that directory; otherwise drop it, or the
# hooks written below would never run.
if local_path="$(git config --local --get core.hooksPath)"; then
  case "$local_path" in
    /*) resolved="$local_path" ;;
    *) resolved="$top/$local_path" ;;
  esac
  if [ "$(canon "$resolved")" != "$(canon "$hooks")" ]; then
    git config --local --unset-all core.hooksPath
    say "removed core.hooksPath=$local_path from this repository's config: it ran hook code from the checked-out branch"
  fi
fi
effective="$(git rev-parse --path-format=absolute --git-path hooks)"
if [ "$(canon "$effective")" != "$(canon "$hooks")" ]; then
  say "core.hooksPath is set outside this repository's config, so git would ignore $hooks"
  say "see: git config --show-origin --get-all core.hooksPath -- unset it, then re-run this script"
  exit 1
fi

mkdir -p "$hooks"
for name in pre-commit pre-merge-commit; do
  if [ -e "$hooks/$name" ] && ! grep -qxF "$MARK" "$hooks/$name"; then
    say "$hooks/$name exists and was not written by this script; move it aside and re-run"
    exit 1
  fi
done

for name in pre-commit pre-merge-commit; do
  tmp="$(mktemp "$hooks/.$name.XXXXXX")"
  cat > "$tmp" <<HOOK
#!/bin/sh
$MARK
# Sensitive-data check ($name). Runs scripts/check_sensitive.py from the blob
# at a trusted ref (git config epigraph.sensitiveHookRef, default origin/main),
# never from the working tree, so a checked-out branch cannot change the code
# that runs here. Re-run the installer from a trusted checkout to update this
# file; edit the scanner through a reviewed change to the trusted ref.
ref=\$(git config --get epigraph.sensitiveHookRef) || ref=origin/main
blob="\$ref:scripts/check_sensitive.py"
if ! git cat-file -e "\$blob" 2>/dev/null; then
  echo "check-sensitive: cannot read \$blob -- refusing to continue (git fetch origin, or set epigraph.sensitiveHookRef)" >&2
  exit 2
fi
scanner=\$(mktemp "\${TMPDIR:-/tmp}/check_sensitive.XXXXXX") || exit 2
trap 'rm -f "\$scanner"' EXIT
trap 'exit 2' HUP INT TERM
git cat-file blob "\$blob" > "\$scanner" || exit 2
python3 "\$scanner"
HOOK
  chmod 755 "$tmp"
  mv -f "$tmp" "$hooks/$name"
done
say "installed pre-commit and pre-merge-commit in $hooks (scanner from ref: $(git config --get epigraph.sensitiveHookRef || echo origin/main))"
