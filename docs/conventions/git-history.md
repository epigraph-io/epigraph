# Git history on `main`

How history reaches `main`, and what that means for a reader walking it
(backlog `e0a1cce5`). The merge procedure itself is in `CLAUDE.md`,
"Workflow".

## Bisecting main

`main` is built from merge commits: each feature PR is merged into a staging
branch with `git merge --no-ff`, and the staging PR is merged into `main` with
`--merge`, never squashed or rebased. The commits inside a PR are kept as
written, and test-first commits among them may be intentionally red (a failing
test committed before the fix that turns it green). A plain `git bisect` walks
into those commits and can name a red-by-design test commit as the first bad
one. So bisect `main` with `git bisect start --first-parent` (git 2.29 or
later): it tests only the commits on `main`'s first-parent chain, each a state
`main` was actually in, and names the merge that brought the regression in.
Then, if needed, bisect inside that merge's PR, skipping (`git bisect skip`) a
test-first commit whose fix is the next commit.
