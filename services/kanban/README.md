# EpiGraph Kanban

A local kanban board over the EpiGraph backlog. The cards are claims labelled `backlog` that are not labelled `resolved` and are current. You pick cards to develop, and the board starts a headless Claude Code **ultracode** agent for each one in its own git worktree. The agent opens a PR into a staging **integration branch** and flags blockers as it works. You review and accept. When the integration branch is ready, you ship it to `main` with one more PR, and the board retires the shipped backlog claims in EpiGraph.

- `server.py`: backend. Uses only the Python 3.9 standard library and binds to `127.0.0.1` only.
- `static/index.html`: the board UI. A single file with no external scripts.
- `prompts/develop.md`: the prompt template given to each development agent.
- `tests/test_server.py`: end-to-end tests that use stub `claude`/`gh` binaries.

## Run

```bash
python3 services/kanban/server.py                 # port 8097, repo = git toplevel of cwd
python3 services/kanban/server.py --port 8097 --repo ~/Projects/epigraph --no-refresh
```

At startup the server prints `http://127.0.0.1:8097/?t=<token>`. Open that exact URL. The UI saves the token for the tab and then removes it from the address bar. The token is kept in `$KANBAN_HOME/token` (mode 0600) and stays the same across restarts.

Prerequisites: `git`, an authenticated `gh`, and `claude` on PATH, plus a checkout of the repo whose `origin` is on GitHub.

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `KANBAN_HOME` | `~/.epigraph-kanban` | Holds `state.json`, `token`, `worktrees/<id8>`, `logs/<id8>-<run>.jsonl` |
| `EPIGRAPH_API_BASE` | `http://127.0.0.1:8080` | EpiGraph HTTP API used for the backlog fetch |
| `EPIGRAPH_TOKEN` | – | Bearer token for the API |
| `EPIGRAPH_JWT_SECRET` | – | Used when no token is set: the server mints an HS256 service JWT (`scopes=["claims:read"]`) |
| `EPIGRAPH_CLIENT_ID` | `5997f752-…` | `sub` of the minted JWT |
| `KANBAN_BACKLOG_SOURCE` | `auto` | `http`, `claude` (asks headless Claude to call the MCP `query_claims_by_label`), `file` (you POST `/api/backlog/import`), or `auto` (tries http first and falls back to claude if http errors or returns 0 items) |
| `KANBAN_CLAUDE_BIN` / `KANBAN_GH_BIN` / `KANBAN_GIT_BIN` | `claude` / `gh` / `git` | Executables |
| `KANBAN_MAX_AGENTS` | `3` | Number of agents that run at once. Extra cards wait as `queued` (FIFO) |
| `KANBAN_PERMISSION_MODE` | `auto` | `--permission-mode` passed to every agent |
| `KANBAN_MODEL` | – | Optional `--model` value |
| `KANBAN_INTEGRATION_PREFIX` | `integration/kanban-` | Integration branches are named `<prefix>YYYY-MM-DD[-N]` |
| `KANBAN_BASE_BRANCH` | `main` | The production branch |
| `KANBAN_REMOTE` | `origin` | The git remote |
| `KANBAN_HTTP_LOG` | – | Set to any value to log each HTTP request to stderr |
| `KANBAN_AGENT_ENV_ALLOW` | – | Comma-separated extra environment variable names that agents may inherit (see below) |
| `KANBAN_AGENT_ALLOWED_TOOLS` | `Read,Edit,Write,Glob,Grep,TodoWrite` | `--allowedTools` for development agents. `Bash` is deliberately left to `--permission-mode` |
| `KANBAN_AGENT_DISALLOWED_TOOLS` | merge/admin `gh` and `git push` patterns, `curl`, `wget`, backlog-mutating MCP tools | `--disallowedTools` for development agents |
| `KANBAN_BACKLOG_TOOL` / `KANBAN_RESOLVE_TOOL` | `mcp__epigraph__query_claims_by_label` / `mcp__epigraph__resolve_backlog_item` | The one MCP tool each helper agent may call |

### What agents inherit

Agents never get the board's environment. Every `claude` the board starts (development, resume, backlog fetch, retirement) gets an allow-listed environment. The list is `PATH HOME USER LOGNAME SHELL LANG LANGUAGE TERM TZ TMPDIR XDG_CONFIG_HOME XDG_CACHE_HOME XDG_DATA_HOME CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR CLAUDE_CONFIG_DIR`, plus `LC_*`, plus whatever `KANBAN_AGENT_ENV_ALLOW` names. `GIT_TERMINAL_PROMPT=0` is always set. A few names are never passed, even if allow-listed: `EPIGRAPH_TOKEN`, `EPIGRAPH_JWT_SECRET`, `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, `GITHUB_ENTERPRISE_TOKEN`, `DATABASE_URL`, `MIGRATION_DATABASE_URL` and every `KANBAN_*`.

Some consequences follow from this:

- Agents push and open PRs with `gh` and `git` credentials from their **config files** (`gh auth login`, a git credential helper, `~/.ssh`), not from environment tokens. If your `gh` authenticates only through `GH_TOKEN`, agents cannot open PRs.
- If `claude` authenticates through an environment variable rather than its credentials file, add that name to `KANBAN_AGENT_ENV_ALLOW`.
- `SSH_AUTH_SOCK` is not passed by default. Add it if pushes go over ssh with an agent.

Tool restrictions:

- **Development agents** get `--allowedTools` and `--disallowedTools` from the table above.
- **Helper agents** (backlog fetch and retirement) get `--tools ""` (no built-in tools at all), `--allowedTools <one MCP tool>` and `--permission-mode dontAsk`, so any other call is denied rather than prompted for. Their `--permission-mode` does not come from `KANBAN_PERMISSION_MODE`.
- The backlog fetch runs in `$KANBAN_HOME/helper-cwd`, not in your checkout.

`GET /api/state` returns the effective configuration under `.config`. Secrets appear only as booleans.

## Columns and statuses

```
backlog --develop--> develop --agent exits--> review --accept--> accepted --ship--> shipped
   ^                    |  ^                    |  |
   |                    |  +----feedback--------+  |
   +-------reject-------+--------------------------+
```

- **Columns:** `backlog`, `develop`, `review`, `accepted`, `shipped`.
- **Status** (a separate field from the column): `idle`, `queued`, `running`, `awaiting_review`, `merging`, `merged`, `failed`, `stopped`.
- **Blockers are flags on a card, not a column.** They come from two places. The agent writes them live to `.kanban/blockers.jsonl` and also lists them in `.kanban/report.json`. You can add them yourself in the UI. `blocker` severity prevents Accept unless you use `force`. `warning` is informational.
- When the agent exits, the card moves to **review** no matter how the run went, so you always see the result. If the agent wrote no report and no PR exists, the card's status becomes `failed` and it gets an automatic blocker.
- **Develop** works from `backlog`, from `review` (re-run with a fresh session), or on a `failed`/`stopped` card in `develop`. **Request changes** resumes the same Claude session (`--resume <session_id>`) in the same worktree, and the agent pushes to the same PR. **Stop** kills the agent's process group. **Reject** moves the card back to `backlog` and leaves its PR open. Pass `cleanup: true` to also remove the worktree.
- If a card is in the `backlog` column and disappears from the backlog source, it is marked `stale`. Cards are never deleted automatically.
- After a server restart, a card that was `running` is reattached if its pid is still alive. Otherwise it is marked `failed`. `queued` cards stay queued.

## The PR tree

```
main
 └── Integration PR: integration/kanban-2026-09-18 -> main        (Ship = merge this)
      ├── kanban/1a2b3c4d-fix-widget -> integration/...            (Accept = merge this)
      └── kanban/5e6f7a8b-add-thing  -> integration/...
```

1. The first develop run with no open integration branch creates one. The server pushes `origin/main` to a new branch `<prefix><date>` and adds a `-2`, `-3`, … suffix if that name already exists on the remote.
2. Each card gets branch `kanban/<id8>-<slug>` in the worktree `$KANBAN_HOME/worktrees/<id8>`, based on the integration branch. The agent pushes the branch and runs `gh pr create --base <integration> --head <branch>`.
3. **Accept** first confirms with one `gh pr view` that the PR is `OPEN`, comes from the card's branch in this repository (not a fork: `isCrossRepository` must be `false`), and targets the current integration branch. It then runs `gh pr merge <n> --merge --delete-branch --match-head-commit <sha>`, pinned to the head it just verified. This merges the item into staging, not into main. The worktree is removed afterwards.
4. **Open integration PR** opens (or reuses) `integration -> main`. It reuses an existing PR only after `gh pr view` confirms the PR is an open, same-repository PR from the integration branch into the configured base branch. A recorded PR that no longer matches is forgotten. The PR body lists the member PRs and backlog claim ids.
5. **Merge integration → main** gets the same checks as Accept (base, head, state, not a fork, head sha) and merges with `--match-head-commit`. There is no unpinned merge. A missing or malformed head sha is refused. All accepted cards move to `shipped`, and the next develop run starts a new integration branch. If "resolve backlog items" is checked (the default), a background `claude -p` run calls the EpiGraph MCP `resolve_backlog_item(original_id, resolution_content)` for each shipped card, citing both PRs. The result is recorded in each card's history (`backlog_resolved: true|false`).

**CI is required on both merge paths.** Accept and Ship both refuse unless the PR's CI checks are `pass`. The check state is read in the same `gh pr view` that supplies the pinned head sha. `pending`, `fail` and `none` (no checks reported) all refuse. The only way past is `"override_checks": true` (a JSON boolean) in that one request's body. The override is never stored, and `force` does not imply it. The server logs each override, and it is recorded in the card history (`checks_overridden`) and in `integration_history` (`checks_at_merge`). The UI shows the check state in the Ship dialog and asks separately before sending the override. Do not assume the hosting platform enforces checks on its own; treat this board as the gate.

The board refuses to ship while cards that target the current integration branch are still in develop or review. Merging would delete the branch, and GitHub would then close their PRs. Accept or reject those cards first, or pass `force: true` to the API. **Start new integration branch** is refused while accepted but unshipped cards exist.

## HTTP API

Every `/api/*` call needs the token: the `X-Kanban-Token` header, or `?t=` for GET only. Other rules:

- Requests are refused unless `Host` is `127.0.0.1:<port>` or `localhost:<port>`. This blocks DNS rebinding.
- A POST whose `Origin` header points to another origin is refused.
- Errors come back as `{"error": "..."}`: 401/403 for auth, 404 for an unknown card, 409 for an invalid transition, 502 when `gh` or `git` fails.

`GET /api/state`, `POST /api/backlog/refresh`, `POST /api/backlog/import` (JSON array), `GET /api/cards/{id}`, `GET /api/cards/{id}/log?tail=300`, `POST /api/cards/{id}/{develop|stop|feedback|accept|reject}`, `POST /api/cards/{id}/blockers`, `POST /api/cards/{id}/blockers/{bid}/resolve`, `GET /api/integration` (cached for 20 s), `POST /api/integration/{open-pr|merge|new}`.

## Agent contract

`prompts/develop.md` has these placeholders: `{claim_id} {content} {labels} {branch} {integration_branch} {base_branch} {worktree} {remote} {feedback_section}`. `{content}` is filled with the claim text already wrapped in a code fence that is longer than any fence inside the text, so the claim is presented as data. The rendered prompt always starts with `ultracode`. The agent must:

- follow `CLAUDE.md`, including the Epistemic Commit Protocol and the rule never to use the live `epigraph` DB for tests
- stay within the scope of its one item
- never merge, never touch `main`, and never call `resolve_backlog_item`
- open its PR against the integration branch
- **always** write `.kanban/report.json`:
  `{status: done|blocked|failed, summary, pr_url, pr_number, blockers: [{text, severity}], verification}`.

`.kanban/` ignores itself: the board writes `.kanban/.gitignore` containing `*`, so the directory is never committed and nothing outside the worktree is edited. The repository's shared `info/exclude` is not touched (from a linked worktree, that file belongs to the main checkout).

## Safety notes

- Each agent runs in its own worktree with `--permission-mode $KANBAN_PERMISSION_MODE` (default `auto`). An agent still has your shell, `gh`, and network credentials. Choose a mode you are comfortable with, and keep `KANBAN_MAX_AGENTS` low.
- Only a human can merge to `main`: the "Merge integration → main" button in the UI. Agents are told never to merge. The board itself merges only when you click Accept or Ship.
- Commands are run as argv lists with explicit timeouts. Nothing goes through a shell. Card ids are checked to be UUIDs before they are used in paths, and branch slugs are limited to `[a-z0-9-]`.
- Claim text is untrusted. The prompt fences it as data, and the UI inserts it with `textContent` only.
- State is saved atomically (a tmp file, then rename) under one lock. Git operations on the main checkout are serialized.

## Limitations

- **MCP in headless mode:** the `claude` backlog source and backlog resolution both depend on the EpiGraph MCP server being available to headless `claude -p`. MCP servers configured as claude.ai connectors may not load in headless or `--print` sessions. If resolution fails, the card history says so. Retire the items by hand with `resolve_backlog_item`. For fetching, `KANBAN_BACKLOG_SOURCE=http` with `EPIGRAPH_TOKEN`/`EPIGRAPH_JWT_SECRET` is the most reliable option.
- Accept uses `gh pr merge --delete-branch` from the main checkout. If gh fails to delete the local branch but GitHub reports the PR `MERGED`, the merge is still treated as successful.
- The board does not rebase item PRs when the integration branch moves. Conflicts show up in the Integration panel as `mergeable`/`checks` status, and you resolve them with Request changes.
- Only one integration branch is active at a time, and one server should run per `KANBAN_HOME`.

## Tests

```bash
cd services/kanban && python3 -m unittest discover -s tests -v
```

The tests create a temporary bare `origin` repo and a clone, plus stub `claude`/`gh` scripts. They then drive the full flow: import → develop → review (live blocker plus report blockers) → resolve blocker → accept → open integration PR → merge → shipped → backlog resolution. They also cover feedback/resume, reject, auth/Host/Origin rejection, 404, and 409.
