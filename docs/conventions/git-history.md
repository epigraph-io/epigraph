# Git history on `main`

How history reaches `main`, and what that means for a reader walking it
(backlog `e0a1cce5`). The merge procedure itself is in `CLAUDE.md`,
"Workflow".

## Bisecting main

`main` is built from merge commits, never squashed or rebased. Feature PRs
normally reach it through a staging branch: each is merged into the staging
branch with `git merge --no-ff`, and the staging PR is merged into `main` with
`--merge` (a PR merged straight to `main` is merged with `--merge` too). The
commits inside a PR are kept as written, and test-first commits among them may
be intentionally red (a failing test committed before the fix that turns it
green). A plain `git bisect` walks into those commits and can name a
red-by-design test commit as the first bad one. So bisect `main` with
`git bisect start --first-parent` (git 2.29 or later): it tests only the
commits on `main`'s first-parent chain, each a state `main` was actually in,
and names the merge into `main` that brought the regression in. When that is a
staging merge, bisect its second parent the same way, with `--first-parent`,
to find the feature PR's merge. Only then bisect inside that PR, skipping
(`git bisect skip`) a test-first commit whose fix is the next commit.
