# Label-family dedup: `plan_label_dedup`, `apply_label_dedup`, `probe_label_dedup`

Some claim families are kept as an index: every live member carries one family
label, and readers query that label. These three MCP tools keep such an index
clean (duplicates, partial retirements, past-due items, signals that
materialized) by **label writes only**. Claim content is never rewritten, no
claim is superseded, and every change is reversible by patching the labels
back.

The planner is the pure engine `epigraph_engine::label_dedup`; the tools are
`crates/epigraph-mcp/src/tools/label_dedup.rs`.

## The profile

Every family rule (labels, parser layout, id rules, aliases, precedence, write
templates) lives in a `label-dedup-profile/v1` JSON document. Nothing
deployment-specific is built in: every list defaults to empty.

`profile_hash` is REQUIRED on every call: the BLAKE3 hex digest of the exact
profile bytes. A profile that hashes differently is refused
(`PROFILE_HASH_MISMATCH`).

How the profile reaches the tool depends on the transport:

| Transport | Accepted | Refused |
|---|---|---|
| stdio | `profile_path`, resolved under `EPIGRAPH_MCP_PROFILE_ROOT` | `profile_json` (`PROFILE_JSON_REFUSED`) |
| HTTP | `profile_json` | `profile_path` (`PROFILE_PATH_REFUSED`) |

On stdio:

- With no `EPIGRAPH_MCP_PROFILE_ROOT`, path mode is off (`PROFILE_PATH_REFUSED`).
- When `EPIGRAPH_MCP_PROFILE_PIN` is set, `profile_hash` must equal it
  (`PROFILE_HASH_MISMATCH`) before the file is even opened. The pin is set by
  whoever starts the process, so the agent talking to it cannot choose another
  profile.
- The path may be relative to the root or absolute under it. `..` is refused.
  Every component below the root is checked with `lstat`, and a symlink anywhere
  is refused. The file is opened `O_NOFOLLOW | O_NONBLOCK` and must be a
  regular file (a FIFO or a directory is refused, never waited on). The size
  limit is 1 MiB.
- A missing file and an unreadable file give the same answer
  (`PROFILE_NOT_FOUND`).

`profile_claim_id` (a profile stored as a claim) is reserved and refused
(`PROFILE_CLAIM_DEFERRED`).

Both variables are read once at startup. An empty value means unset.

## Reads

Each family is read in one statement:
`ClaimRepository::list_all_by_labels_ordered_by_id(conn, viewer, include, exclude, current_only, cap)`.
It has no offset, orders by id, and reads `cap + 1` rows so that a family
larger than the cap is detected.

All reads run on one connection stamped from the caller's viewer
(`ScopedPool::read_as`). The caller therefore sees exactly the rows it may
read: its own group-private rows included, other groups' private rows never.

`max_claims` defaults to 5000, which is also the server cap. A larger request
is clamped, and the response reports `max_claims: {requested, effective,
clamped}`. A read that hits the cap sets `coverage.truncated`.

Every claim the caller can read that carries the family label is a member.
That includes another author's public claim, so membership is not ownership.
Apply and probe therefore check ownership themselves (next section).

## Ownership of a cluster

The engine has no owner field, and a revision label on either claim of a pair
links them, so another author can make a claim of theirs a member of the
caller's cluster, and, if it is newer, its survivor. A cluster unit retires its
losers toward its survivor, so:

- every member of a cluster unit, the survivor included and whether or not
  that member is itself written, must be the write identity's own: its
  author, an agent of the author's operator, or, over HTTP, a `claims:admin`
  caller (the same decided grants as `require_owner_or_admin`);
- a stdio server with no declared signer cannot decide this for another
  agent's claim, and undecided is not owned;
- a cluster with any other member fails as a unit with `CROSS_OWNER_MEMBER`
  and writes nothing. Membership comes from the plan's cluster records, not
  from the unit's writes: a survivor with nothing to write is still checked.

Probe applies the same check: a `match` or `match_only` on a claim the caller
does not own becomes `review`, with `matched_id` kept for the human.

Hygiene, close-out and lifecycle units involve one claim each and keep
`update_labels`' per-claim gates (below). A lifecycle `graduated` close and a
signal supersession name a target member as the reason; that target is not
ownership-checked today.

## `plan_label_dedup` (claims:read)

It returns:

- `plan_hash`;
- `coverage` (`members`, `truncated`, `snapshot_at`);
- `hygiene`, `clusters`, `review_pairs`, `vetoed_chains`, `past_due`,
  `lifecycle` and the signal sections;
- `write_units`: exactly the writes apply would make, one transaction each, in
  apply order;
- `write_check`, per write target;
- `unit_check`, per unit: `{unit, applies, members}`, where `members` lists
  every member of a cluster unit with `owned` and a `reason` when not.

`plan_hash` covers `profile_hash`, `run_tag`, `as_of`, the normalized sections
and the write units, and nothing else. A new review pair therefore never causes
drift.

`write_check` is a **prediction** made under the caller's write identity, per
write target. It uses the same non-writing gates `update_labels` runs:
ownership over HTTP, the retirement-label gate, and whether the owner group is
writable (or reachable through the admin path). It never writes. Row-security
refusals that only the database decides are reported by apply, per unit.
`unit_check.applies` is false when any write target is predicted unwritable or
any cluster member is not the write identity's own; apply's
`CROSS_OWNER_MEMBER` comes from the same check.

## `apply_label_dedup` (claims:write; refused on a read-only server)

1. Re-plan from live state with the same arguments.
2. If any read was truncated, return `status: refused`, `refusal.code:
   TRUNCATED`, and write nothing. A family over the engine's pairwise bound
   (see `RESOURCE_CAP` below) is likewise `status: refused`,
   `refusal.code: RESOURCE_CAP`, with `plan: null`.
3. If the fresh `plan_hash` differs from the argument, return `status:
   refused`, `refusal.code: PLAN_DRIFT`, with the fresh `plan`, and write
   nothing. Review the fresh plan, then apply its hash.
4. If there are no writes, return `status: nothing_to_do`. A re-run after a
   successful apply looks like this.
5. Otherwise write each unit in **one transaction**, stamped from the write
   identity:
   - a unit is a cluster (survivor carry labels plus every loser's retirement),
     one hygiene claim, one close-out claim, or one lifecycle signal;
   - a cluster unit first checks that every member is the write identity's
     own (`CROSS_OWNER_MEMBER` otherwise, nothing written);
   - each claim goes through `update_labels`' own per-claim path
     (`tools::claims::relabel_claim`): over HTTP, ownership or `claims:admin`
     (the audited admin path for a group the caller cannot write); on every
     transport, the ownership gate for `resolved` and for the profile's closed
     label;
   - a refused claim fails its whole unit, so no "looks merged but isn't"
     state is left. Later units continue.

The response contains:

- `status`: `applied`, even when some units failed (see `results` and
  `counts.failed`);
- `results`: one `{unit, ok, code?, error?, admin_path}` per unit;
- `counts`;
- `applied_units`.

`applied_units` lists one `{unit, claim_id, labels_added, labels_removed}` per
committed write, in apply order. A label appears only if this write changed it:
a label the write named that was already in the requested state is not listed,
and neither is any label the write did not name (such as another writer's
concurrent change to other labels). Rolled-back units are absent.

## Revert procedure

Use it to undo an apply, for example when an apply generation mis-merged. Its
input is the `applied_units` of that apply, exactly as returned.

1. Compute the inverse with `epigraph_engine::label_dedup::revert_writes(&applied_units)`.
   It reverses the list (newest change first) and swaps added and removed
   labels. It drops empty changes.
2. Run each resulting write, in order, through `update_labels(claim_id, add,
   remove)` under the same identity (or one with the same ownership) that ran
   the apply.
3. Re-plan with the original arguments. When nothing else changed the family
   meanwhile, the plan is the original one again: the same `plan_hash`.

The order matters when two units touched the same claim and label: one adds
it, a later one removes it. Only newest-first lands back on the original set.

What it restores, and what it does not:

- **Label sets, exactly.** The write path stores a claim's labels sorted and
  distinct. A claim whose labels were stored in another order (or with
  duplicates) before the apply comes back with the same set, in sorted order.
  Restoring the stored order would need a direct row write, which no tool
  offers.
- **Retirements.** Removing `resolved` (or the profile's closed label) takes the
  same ownership gate as adding it. The identity that applied can revert. A
  close-out made over HTTP through the audited admin path (`claims:admin` on a
  group the admin cannot write) is reverted the same way, by the same admin
  token. That writes a second `claims.admin_write` audit row. The tests cover
  the stdio owner path only; the admin-path revert follows from
  `update_labels` taking the same admin path in both directions.
- **Concurrent edits.** A label that someone else added or removed after the
  apply, and that the apply had also changed, is changed back by the revert.
  Check the family's recent history before reverting a long-past apply.

The procedure is tested end to end against an application-role database in
`crates/epigraph-mcp/tests/label_dedup_tools.rs`
(`apply_then_revert_from_applied_units_restores_every_label_set`), and the
inverse itself in `crates/epigraph-engine/tests/label_dedup/revert.rs`.

## `probe_label_dedup` (claims:read)

It classifies up to 100 would-be claims against the live family index, using
the rules a plan uses. Each verdict is one of:

- `new`: file it;
- `match`: an auto-merge rule matched a live member (`matched_id`, `tier`);
- `review`: a human decides (also a match on a claim the caller does not
  own);
- `match_only`: it matched only a closed signal (with
  `include_closed_signals`).

A truncated index read is refused (`TRUNCATED`) rather than answered `new`.

## Refusal codes

Tool errors carry `data.code`:

- `PROFILE_PATH_REFUSED`
- `PROFILE_JSON_REFUSED`
- `PROFILE_NOT_FOUND`
- `PROFILE_TOO_LARGE`
- `PROFILE_SOURCE_REQUIRED`
- `PROFILE_CLAIM_DEFERRED`
- `PROFILE_HASH_MISMATCH`
- `PROFILE_SCHEMA_INVALID`
- `INVALID_ARGUMENT`
- `AS_OF_REQUIRED`
- `SECTION_NOT_CONFIGURED`
- `INVALID_RUN_TAG`
- `INVALID_LABEL`
- `TOO_MANY_CANDIDATES`
- `RESOURCE_CAP` (the engine bounds the pairwise pass: at most
  `MAX_DEDUP_FAMILY_MEMBERS` members per dedup pass, plus edge and
  review-pair bounds; a family that reads in under `max_claims` can still be
  refused here)
- `TRUNCATED` (probe)

Apply's `TRUNCATED`, `RESOURCE_CAP` and `PLAN_DRIFT` are a `refused` status, not
an error. A failed unit carries its code in `results[].code`, for example
`CROSS_OWNER_MEMBER`.
