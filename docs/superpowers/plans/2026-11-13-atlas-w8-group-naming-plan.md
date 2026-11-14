# Atlas W8: LLM names for every group, in both hierarchies (plan)

Backlog item W8 a71816e1 (epic 8fa0282d). Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
(§2 "Every group at every level is named by an LLM", "LLM naming runs from
prod through the existing Claude CLI path"; §3 goal 3; §5 "No leak through
names or shape"; §7 step 6 and "LLM naming cost control").

Stacked on `atlas/wave3-base` (W1 #802, W2 #803, W3 #805, W10a #801, W4 #810).
No migration.

## What this item delivers

A naming step the nightly (W9) calls after W4/W5/W6 have assembled a map's
level documents, and before `write_run`. It fills the W10a contract's name
fields (`name`, `needs_naming`) of every group and leaf of a map, in whatever
hierarchies the documents hold, and the names that other documents repeat:
each `children[]` entry, every breadcrumb, every `targets[]` and
`outgoing[].target`. The theme ROOT of each hierarchy (depth 0) is the
per-map theme name, so a team map gets team-only theme names and the public
map gets public-only theme names (backlog D-PR16's leak, for the Atlas).

`claim_themes.label` is NOT changed here. `scripts/label_themes_llm.py` still
samples team-private text into the global theme label; retiring or
restricting it is a follow-up (the Atlas stops reading it for nested levels
once W10 serves the per-map root names).

## Shape: W6's

| Step | Where | What |
|---|---|---|
| `plan_samples(docs)` | pure | each group's ordered sample candidates (claim ids only) |
| `read_member_texts(conn, viewer, map, ids)` | DB, box | the text of those claims the MAP may draw now: W4's `claim_labels`, which carries W3/W4's map predicate |
| `read_previous(conn, viewer, map)` | DB, box | the latest finished run of the map that carries a naming record: its keys and its names |
| `name_levels(docs, plan, texts, previous, backend, opts)` | pure + the backend | names bottom-up, carries unchanged ones, fills every repeated name, returns the record for `params.naming` |

No transaction is held while the model runs: the reads finish first, then
the model calls, then a short write.

**The library never writes `params`**: it returns a `NamingRecord` and the
caller puts it under `params.naming` when it opens the run, as W6 does with
`params.layout`.

**The binary** `atlas_naming name --map M [--apply] [--max-calls N]` is the
operator path until W9 exists: it reads the map's latest finished run (both
hierarchies), names it, and writes it as a NEW run (a finished run cannot be
changed): every level copied with its `run_id` rewritten, the source run's
`params` kept whole (W4's counts, W6's `layout`) plus `naming`, and the
SOURCE run's four epochs, because the documents describe that snapshot. Dry
run by default, and a dry run makes no model call: it reports how many
groups would be named. `--max-calls` bounds one run; groups past it keep
`needs_naming` and are named on the next run.

## No leaks

A name is generated only from text every viewer of the map can read:
- **member text is read through the map-scoped read**
  (`AtlasMeaningRepository::claim_labels`: `visibility = 'public' OR
  (visibility = 'group' AND owner_group_id = T)`, T NULL for the public
  map), never from the document's `label` field. A claim the documents still
  list but the map may no longer draw (it narrowed, or moved team since the
  build) contributes nothing;
- the prompt holds only those texts and the names of the group's children,
  which were themselves made under the same rule;
- **the carry-over key covers everything the prompt drew on**, so a name is
  copied only when the model would see the same input now (below).

## Cost control: the key

`key = SHA-256("atlas-names" ‖ PROMPT_VERSION ‖ map ‖ theme ‖ prompt)`, lower
hex, where the prompt holds the sampled member texts (in sample order, hence
their ids) and, for an inner group, its children's names. It is the "hash of
the sampled member ids plus the prompt version" of the item text, widened to
the children's names and the texts because a carried name must never rest on
an input that has since changed (a narrowed child renamed, its parent must
be renamed too).

**Carry-over is by key, not by group id.** A non-root group id changes with
any change to its members, so carrying by id would rename every ancestor of
every touched leaf each night. By key, a group is renamed only when its
sample or its children's names changed. Unchanged groups copy their previous
name with zero model calls. Groups whose naming failed are not recorded, so
they are retried.

Within one run, two groups with the same key share one call (a theme small
enough to be one leaf is the root of both hierarchies with the same input,
so both get the same name).

Stored in the run's `params`:

```json
{"naming": {"prompt_version": "atlas-names/1",
            "keys": {"meaning/<group id>": "<64 hex>", "links/<group id>": "..."}}}
```

The contract is closed (`deny_unknown_fields`), so the key cannot ride in
the document; `params` is the builder's slot (W6's reasoning). About 110
bytes per named level; measure on prod.

## Sampling and the prompt

- Deterministic, by id hash: a leaf's candidates are its claim nodes ordered
  by SHA-256 of the claim id; an inner group's are its children's candidate
  lists interleaved round-robin in child order, deduplicated. The first
  `2 × N` candidates are read; the sample is the first `N` (12) with readable
  text. A new claim enters a sample only if its hash ranks in it, so most
  groups' samples (and so their names) are stable night to night.
- Each text is whitespace-collapsed and cut to 300 characters.
- Inner groups also list up to 40 of their children's names (named first:
  the step runs bottom-up).
- The model is asked for a JSON object `{"name": "..."}`: a 2 to 6 word noun
  phrase. The contract has no description field, so none is asked for.

**Reply validation** (`validate_reply`): the JSON object (a code fence and
surrounding prose are tolerated), a string `name`, trimmed of quotes and a
final period; refused when empty, over 80 characters or 8 words, holding a
control character (a newline included), or sharing a run of 5 consecutive
words with any sampled text (it quotes a claim instead of naming the group).
A refused or failed reply leaves `name` null and `needs_naming` true, with
no key recorded.

## The model backend

`trait NameBackend { fn complete(&self, prompt: &str) -> Result<String, BackendError>; }`

- `ClaudeCliBackend` spawns `claude -p --output-format json --max-turns 1
  --model <model>` (the model `label_themes_llm.py` uses by default), the
  prompt on stdin, `ANTHROPIC_API_KEY` and `CLAUDECODE` removed from its
  environment (the `scripts/lib/claude_cli.py` pattern: the CLI's own OAuth,
  never an API key, never the SDK), in an empty owner-only working
  directory, killed (only that child) at a timeout. A non-zero exit,
  `is_error`, an empty `result` or a timeout is a failed reply, never an
  abort of the run. The program path is injectable, so a test runs a stub
  script in its place.
- `RecordingBackend` (tests): a scripted reply function, a call counter and
  every prompt it received.

## Files

| File | What |
|---|---|
| `crates/epigraph-cli/src/atlas_naming/mod.rs` | module doc, re-exports |
| `crates/epigraph-cli/src/atlas_naming/backend.rs` | `NameBackend`, `ClaudeCliBackend`, `RecordingBackend` |
| `crates/epigraph-cli/src/atlas_naming/prompt.rs` | sampling order, the prompt, the key, `validate_reply` |
| `crates/epigraph-cli/src/atlas_naming/name.rs` | pure: `plan_samples`, `name_levels`, the consistency pass, `NamingRecord` |
| `crates/epigraph-cli/src/atlas_naming/build.rs` | DB halves: `read_member_texts`, `read_previous`, `name_map` (the binary's read, name, write) |
| `crates/epigraph-db/src/repos/atlas_naming.rs` | the run reads: latest finished run, latest named run, a run's levels, a run's names (each spliced on the viewer) |
| `crates/epigraph-cli/src/bin/atlas_naming.rs` | the operator binary, `MAINTENANCE_DATABASE_URL` only |
| `crates/epigraph-cli/tests/atlas_naming.rs` | DB tests (fresh DB, `remote-cargo --db`) |

## Tests

**Pure** (in `atlas_naming`):
- the sample is deterministic and independent of node order;
- an inner group's key changes when a child's name changes;
- every repeated name equals its group's own name after the pass, and a name
  not in the run is null on a breadcrumb or link target;
- invalid replies (not JSON, a newline, too long, too many words, a 5-word
  quote, empty) fall back, with no key recorded, and are retried next run;
- `--max-calls` stops calling and leaves the rest flagged;
- synthetic links documents are named like meaning ones;
- every named document passes `to_stored_json`;
- `ClaudeCliBackend` against stub scripts: the stub refuses unless
  `ANTHROPIC_API_KEY` and `CLAUDECODE` are absent and `-p` is passed; an
  `is_error` envelope, an empty result and a hang (killed at the timeout)
  are errors.

**DB** (`crates/epigraph-cli/tests/atlas_naming.rs`), meaning levels from
W4's apply plus synthetic links levels in the same run; a backend that copies
the first `TOK…` marker of its prompt into the name, so a leaked text would
show in the stored name:
- `a_team_maps_names_never_draw_on_another_teams_private_text`: two teams
  and public claims in one theme; after the build a team-A claim moves to
  team B; no prompt for A's map holds a B marker or the moved claim's marker,
  and no stored name does;
- `the_public_maps_prompts_hold_only_public_text`: after the build a public
  claim narrows to a team; every marker in every public-map prompt is a claim
  that is public now;
- `a_name_drawn_from_a_claim_that_narrowed_is_replaced`: named while public,
  then narrowed, then renamed: no stored public name holds its marker;
- `a_rerun_over_unchanged_groups_makes_zero_calls`: a second build over
  unchanged input, then naming: 0 calls, every name copied;
- `a_changed_group_triggers_exactly_one_call`: one claim added to a theme
  that is one root leaf: exactly 1 call, for that theme;
- `stored_named_documents_validate_and_agree`: every stored document of the
  named run passes `parse_and_validate`; children, breadcrumbs agree with the
  named groups; `run_id` is the new run; params kept plus `naming`; epochs
  are the source run's;
- `the_binary_refuses_a_bad_map_before_connecting` (no DB).

## How each "Done when" is proven

| Criterion | Test |
|---|---|
| a team map's names never draw on another team's private text | `a_team_maps_names_never_draw_on_another_teams_private_text` (+ `the_public_maps_prompts_hold_only_public_text`, `a_name_drawn_from_a_claim_that_narrowed_is_replaced`) |
| a rerun over unchanged groups makes zero LLM calls | `a_rerun_over_unchanged_groups_makes_zero_calls` (and the pure `a_rerun_makes_no_call`) |

**Fail on old code** (measured on the branch: each mutation applied alone,
the unit and DB targets run, then restored and `touch`ed):

| Mutation | Tests that went red |
|---|---|
| member text taken from the documents' `label` fields | `a_team_maps_names_never_draw_on_another_teams_private_text`, `the_public_maps_prompts_hold_only_public_text`, `a_name_drawn_from_a_claim_that_narrowed_is_replaced` |
| `claim_labels` without the map predicate | the same three |
| key over the texts only (children's names left out) | `a_parent_is_renamed_when_a_child_name_changes`, `the_key_covers_the_children_names_the_members_and_the_map` |
| carry-over by group id, ignoring the key | `a_parent_is_renamed_when_a_child_name_changes`, `a_changed_group_triggers_exactly_one_call`, `a_name_drawn_from_a_claim_that_narrowed_is_replaced` |
| no carry-over at all | `a_rerun_makes_no_call`, `a_parent_is_renamed_when_a_child_name_changes`, `a_rerun_over_unchanged_groups_makes_zero_calls`, `a_changed_group_triggers_exactly_one_call` |
| no sharing of one key within a run | `links_levels_are_named_and_an_identical_input_is_one_call`, `a_changed_group_triggers_exactly_one_call` |
| validation accepts a control character (newline) | `invalid_replies_are_refused`, `invalid_replies_fall_back_and_are_retried` |
| validation accepts a 5-word quote | `invalid_replies_are_refused`, `invalid_replies_fall_back_and_are_retried` |
| `ANTHROPIC_API_KEY` / `CLAUDECODE` not removed | `the_cli_runs_without_an_api_key` |
| named run records a fresh snapshot's epochs | `stored_named_documents_validate_and_agree` |
| named run drops the source's params | `stored_named_documents_validate_and_agree` |
| children's names not rewritten | `repeated_names_agree_with_each_group`, `stored_named_documents_validate_and_agree` |

Not mutation-proved (direct properties): `a_plain_reply_is_accepted_and_trimmed`,
`texts_are_clipped_and_flattened`, `the_sample_is_deterministic_and_order_free`,
`the_budget_and_a_dry_run_defer_the_rest`, the stub-script error cases, and
`the_binary_refuses_bad_arguments_before_connecting`.

## Decisions to check

- Carry-over by key, not by group id (above).
- The meaning and links roots of a theme are named separately (their
  children differ); they share a name only when their whole input is equal (a
  theme that is one leaf).
- No description: the contract has no field for one.
- The binary keeps the source run's `algo` and adds `named_from_run` to the
  params.
- `claim_themes.label` is untouched. `label_themes_llm.py` still writes
  team-private-sampled text into the global theme labels; the follow-up is to
  retire it or restrict it to public text once W10 serves the per-map root
  names.

## Needs prod measurement

Groups per map (levels per run) and per-call latency of `claude -p` on the
box: together the first full naming run's duration and the `--max-calls`
setting; the size of `params.naming` on the largest team map.
