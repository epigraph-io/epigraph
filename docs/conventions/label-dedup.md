# Label-family dedup: `plan_label_dedup`, `apply_label_dedup`, `probe_label_dedup`, `revert_label_dedup`, `label_dedup_index_view`

Some claim families are kept as an **index**: every live member carries one
family label, and readers query that label (a lead list, a tracker). These
tools keep such an index clean: duplicates, partial retirements, past-due
items, and signals that materialized.

- A duplicate is **marked**, through `mark_duplicate`'s own act. It becomes
  non-current, so it leaves the index read. It keeps its labels, evidence and
  fields, and it gains a `same_as` identity edge to its survivor that records
  why.
- Everything else (hygiene, close-out, lifecycle, the survivor's carried ids)
  is a **label write**.
- Claim content is never rewritten, and one call undoes a whole apply
  (`revert_label_dedup`), but only on a server that holds the administrative
  (maintenance) connection. Request-serving servers hold none and refuse a
  revert with marks, and no shipped surface runs one elsewhere, so today a
  mark is one-way (see
  [duplicates-and-index-hygiene.md](duplicates-and-index-hygiene.md)).

Label dedup is index bookkeeping. It is never a merge of knowledge claims: a
duplicate knowledge claim is marked on its own with `mark_duplicate`. To keep
it that way:

- every family a profile names must be declared `family_kind: "index"`
  (`FAMILY_NOT_INDEX` otherwise);
- the family must be on this server's allowlist,
  `EPIGRAPH_LABEL_DEDUP_INDEX_FAMILIES` (comma-separated, read once at startup;
  empty refuses every family, `FAMILY_NOT_ALLOWED`).

Both checks are decided from the profile alone, before any read.

Not sure label dedup is the right tool? See
[duplicates-and-index-hygiene.md](duplicates-and-index-hygiene.md).

The planner is the pure engine `epigraph_engine::label_dedup`; the tools are
`crates/epigraph-mcp/src/tools/label_dedup.rs`.

## The profile

Every family rule (labels, parser layout, id rules, aliases, precedence, write
templates) lives in a `label-dedup-profile/v2` JSON document. Every pass
declares its `family_kind`, and so does a lifecycle's signal family. Nothing
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

The reads are of **current** claims only, so a marked duplicate is not a
member. Each claim read carries its marked duplicates (the index view below):
the engine reads their fields where the claim's own are read. For example, a
duplicate's later deadline holds off the canonical's close-out.

- A duplicate read that hits the cap truncates the read too.
- Only duplicates of the canonical's own owner count. A claim another owner
  marked onto a public member (a far deadline, say) must not move the
  member's dates. It is left out and listed in
  `coverage.foreign_duplicates_ignored`.

Every claim the caller can read that carries the family label is a member.
That includes another author's public claim, so membership is not ownership.
Apply and probe therefore check ownership themselves (next section).

Row security applies to the duplicates read as well: a duplicate the caller
cannot read is invisible to its plan and to the index view. A caller that must
see every duplicate (a digest of the whole index) needs a viewer that reads
them all.

## Ownership

The engine has no owner field. Another author can make a claim of theirs a
member of the caller's cluster, and its survivor if it is newer: a shared id
does it, and so does a revision label on either claim. A cluster unit marks
its losers onto its survivor, so:

- **Every member of a cluster unit, and every target of any other unit, must
  be the write identity's own.** That means its author, an agent of the
  author's operator, or, over HTTP, a `claims:admin` caller (the same decided
  grants as `require_owner_or_admin`).
  - A stdio server with no declared signer cannot decide this for another
    agent's claim, and undecided is not owned.
  - A member not owned fails the unit with `CROSS_OWNER_MEMBER`; any other
    target fails it with `TARGET_NOT_OWNED`. Nothing of the unit is written.
  - Membership comes from the plan's cluster records, not from the unit's
    writes, so a survivor with nothing to write is still checked.
- **A cluster of more than one owner is never marked, whatever the caller's
  grant (A7), however it was joined.** It fails with `CROSS_OWNER_MEMBER` and
  is listed in apply's `review` for a human.
  - A claim's owner is its author's operator, or the author when it has none.
  - So the same agent, an operator and its agents, and two agents of one
    operator are each one owner.
  - A `claims:admin` caller owns every member and is still refused.
- **A mark is the caller's own act**, on its own stamped transaction, under
  `mark_duplicate`'s rules:
  - the caller must write the duplicate (the act's row security);
  - it must write the group that owns the canonical, since the cascade moves
    other writers' edges and mass functions onto it;
  - the canonical must still be current.

  A `claims:admin` caller therefore cannot mark inside a group it cannot
  write, even where it could relabel through the audited admin path. That
  keeps every mark one its own `unmark_duplicate`, and so the revert, can
  undo.

Probe applies the same ownership check: a `match` or `match_only` on a claim
the caller does not own becomes `review`, with `matched_id` kept for the
human.

## `plan_label_dedup` (claims:read)

It returns:

- `plan_hash`;
- `coverage` (`members`, `truncated`, `snapshot_at`);
- `hygiene`, `clusters`, `review_pairs`, `vetoed_chains`, `past_due`,
  `lifecycle` and the signal sections;
- `write_units`: exactly the writes apply would make, one transaction each, in
  apply order;
- `write_check`, per write target;
- `unit_check`, per unit: `{unit, applies, members, marks, cross_owner,
  review}`:
  - `members` lists every member of a cluster unit, with `owned` and a
    `reason` when not owned;
  - `marks` lists each duplicate the unit marks, with `may_mark`;
  - `cross_owner` is the reason the cluster spans owners, or null;
  - `review` is true exactly when `cross_owner` is set.

`plan_hash` covers `profile_hash`, `run_tag`, `as_of`, the normalized sections
and the write units (marks included), and nothing else. A new review pair
therefore never causes drift.

`write_check` is a **prediction** made under the caller's write identity, per
write target. It uses:

- the ownership check every target takes;
- the gates `update_labels` runs: the retirement-label gate, and whether the
  owner group is writable or reachable through the admin path.

`may_mark` checks the canonical rule above, then asks the dedup act's own
write predicates (`ClaimRepository::session_may_mark_conn`), on a transaction
stamped as the write identity and then rolled back. Nothing is written. An
identity that cannot open a write transaction gets `may_mark: false`, not an
error. Refusals that only the act or the database decides (FA07, a concurrent
change) are reported by apply, per unit.

`unit_check.applies` is false when any of these predictions fails. Apply's
refusals come from the same checks.

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
   - A unit is one of: a cluster (its losers marked, then the survivor's
     labels), one hygiene claim, one close-out claim, or one lifecycle signal.
   - **Ownership first**, as above (`CROSS_OWNER_MEMBER`, `TARGET_NOT_OWNED`,
     or `review`), then the canonical rule (`MARK_REFUSED`). Nothing is
     written before they pass.
   - **Then each mark**, through `mark_duplicate`'s act on this transaction
     (`ClaimRepository::mark_duplicate_act_attributed_conn`). The duplicate
     becomes non-current, its embedding is cleared, and it gains a `same_as`
     identity edge to the survivor. The edge's `properties.dedup` records:
     - `tool: "label_dedup"`;
     - the matching tier as `rule`, and what it matched on as `matched_on`;
     - the `run_tag` and the `plan_hash`;
     - the acting agent.

     The repair (re-pointing the duplicate's edges and moving its mass
     functions onto the canonical; its evidence rows stay with it) is the
     dedup cascade:
     - it runs after the commit, on the administrative connection;
     - on a server without that connection, it is deferred on the same
       transaction and runs at the next replay.

     The duplicate keeps its labels: no loser label is written.
   - **Then each label write**, through `update_labels`' own per-claim path
     (`tools::claims::relabel_claim`):
     - over HTTP, ownership or `claims:admin` (the audited admin path for a
       group the caller cannot write);
     - on every transport, the ownership gate for `resolved` and for the
       profile's closed label.
   - A refused mark or write fails its whole unit, so no "looks merged but
     isn't" state is left. Later units continue.

The response contains:

- `status`: `applied`, even when some units failed (see `results` and
  `counts.failed`);
- `results`: one `{unit, ok, code?, error?, admin_path}` per unit;
- `counts` (`units`, `ok`, `failed`, `marks`, `labels_added`,
  `labels_removed`);
- `review`: one `{unit, reason}` per cluster refused as cross-owner;
- `applied_marks`: one `{unit, dup, canonical, rule, matched_on,
  identity_edge, cascade, belief_cascade}` per committed mark, in apply order;
- `applied_units`.

`applied_units` lists one `{unit, claim_id, labels_added, labels_removed}` per
committed write, in apply order. A label appears only if this write changed it:
a label the write named that was already in the requested state is not listed,
and neither is any label the write did not name (such as another writer's
concurrent change to other labels). Rolled-back units are absent.

## `revert_label_dedup` (claims:write; refused on a read-only server)

Use it to undo an apply, for example when an apply generation mis-merged. Its
input is that apply's `applied_units` and `applied_marks`, exactly as
returned.

A revert with marks needs the administrative connection, which
request-serving servers do not hold: there it is refused
(`ADMIN_CONNECTION_REQUIRED`) with nothing written. A label-only revert (no
`applied_marks`) runs anywhere.

1. Nothing is written until every un-mark is proved admissible:
   - the server's administrative connection must be usable
     (`ADMIN_CONNECTION_REQUIRED` otherwise; an un-mark has no deferred form);
   - each un-mark's own gate must pass, read-only: the claim still carries
     the mark the apply made (the same canonical and, when the input gives
     it, the same `identity_edge`), and the caller has `unmark_duplicate`'s
     authority over it;
   - a canonical that is itself a marked duplicate must be un-marked earlier
     by the same revert.

   Otherwise the call is refused with `UNMARK_REFUSED`, naming every un-mark
   that would fail. The label half alone would leave the marks without the
   labels they were applied with.
2. Then the label writes are undone, newest first
   (`epigraph_engine::label_dedup::revert_writes`: added and removed swapped,
   empty changes dropped). Each runs through `update_labels`' per-claim path
   under the caller's identity.
3. Then the marks are undone, newest first
   (`epigraph_engine::label_dedup::revert_marks`), each through
   `unmark_duplicate`. An un-mark is refused while the duplicate's canonical
   is itself a marked duplicate, which is why the order matters: a chain made
   across applies is undone by reverting the later apply first, or both in
   one call.
4. Re-plan with the original arguments. When nothing else changed the family
   meanwhile, the plan is the original one again: the same `plan_hash`.

Each step is reported (`steps[]`, with `ok` and `error`). A step that still
fails (a race after the proof) does not stop the others, and `status` is then
`partial` instead of `reverted`. One call takes at most 10,000 label changes
and as many marks.
Every step takes the gates its single-claim tool takes, so a revert can do
nothing `update_labels` and `unmark_duplicate` would not let the caller do.

The order of the label writes matters when two units touched the same claim
and label: one adds it, a later one removes it. Only newest-first lands back
on the original set.

What it restores, and what it does not:

- **Index membership, currency and `supersedes`, exactly.** The un-mark puts
  back what the dedup cascade moved, from the record that cascade kept. For a
  mark whose cascade was deferred and has not run, there is nothing to move
  back: the un-mark retires the open deferral instead. The identity edge
  stays, retracted (`valid_to` set), as the audit of the mark and its
  reversal.
- **Label sets, exactly.** The write path stores a claim's labels sorted and
  distinct. A claim whose labels were stored in another order (or with
  duplicates) before the apply comes back with the same set, in sorted order.
  Restoring the stored order would need a direct row write, which no tool
  offers.
- **Retirements.** Removing `resolved` takes the same ownership gate as adding
  it, so the identity that applied can revert. A close-out made over HTTP
  through the audited admin path (`claims:admin` on a group the admin cannot
  write) is reverted the same way, by the same admin token, which writes a
  second `claims.admin_write` audit row.
- **Concurrent edits.** A label that someone else added or removed after the
  apply, and that the apply had also changed, is changed back by the revert.
  Check the family's recent history before reverting a long-past apply.

The revert is tested end to end against an application-role database whose
administrative connection runs as `epigraph_maintenance`, in
`crates/epigraph-mcp/tests/label_dedup_tools.rs`
(`one_revert_after_apply_restores_labels_marks_and_the_index`). Its orders are
tested in `crates/epigraph-engine/tests/label_dedup/revert.rs`.

## `label_dedup_index_view` (claims:read)

For up to 100 canonical claim ids, it returns each canonical with every claim
marked a duplicate of it. It follows a chain: a duplicate of a duplicate is
included.

- The walk follows only **in-force** dedup identity edges (`same_as` carrying
  `properties.dedup`). A plain `same_as` link is not followed, and neither is
  the retracted edge of an un-marked duplicate.
- Use it to read the fields a duplicate kept, such as a later deadline or an
  extra id, where the canonical is.
- It reads through the caller's viewer, as the plan does. An unreadable
  canonical is listed in `missing`.
- Each duplicate carries its `agent_id`. Like the plan, the view leaves out a
  duplicate whose author has another owner than the canonical's, and lists it
  in `foreign_duplicates_ignored` (`{canonical, id}`), so a reader that takes
  dates from the view cannot be moved by a stranger's mark. The plan and the
  view share one owner check. `same_owner_only: false` returns every
  duplicate (and an empty `foreign_duplicates_ignored`). The owner rule runs
  after the `max_claims` cap.
- It takes any claim ids; it does not check the index-family allowlist.
- `max_claims` caps the duplicates read; `truncated` reports a read that hit
  the cap, or a chain deeper than the walk follows (16 marks,
  `MAX_DUPLICATE_CHAIN_DEPTH`). The duplicates past that depth are not
  returned. The plan reports the same as `coverage.truncated`, so apply
  refuses it.

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
- `FAMILY_NOT_INDEX`, `FAMILY_NOT_ALLOWED` (plan, apply and probe, before any
  read; revert and the index view take no profile)
- `ADMIN_CONNECTION_REQUIRED`, `UNMARK_REFUSED` (revert)

Apply's `TRUNCATED`, `RESOURCE_CAP` and `PLAN_DRIFT` are a `refused` status, not
an error. A failed unit carries its code in `results[].code`:

- `CROSS_OWNER_MEMBER`;
- `TARGET_NOT_OWNED`;
- `MARK_REFUSED` (the canonical rule, or the dedup act refused the mark);
- null, for a label write refused by `update_labels`' own gates or an
  internal error (see `error`).
