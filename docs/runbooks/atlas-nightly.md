# Runbook: the nightly Atlas refresh (`atlas_nightly`)

Atlas W9 (backlog 1da9ed16). One binary, run by a systemd timer on the
maintenance DSN, keeps every Atlas map's nested levels current. It replaces
the paused theme-maintenance task: this is the theme-v2 runbook's "rewire the
nightly" step (`docs/ops/theme-v2-promotion-runbook.md`, step 2).

Nothing in the repository installs it. Every step below is an operator step.

## What a night does

1. **Themes.** Assigns every embedded, unthemed claim (superseded ones too,
   as `ClaimThemeRepository::assign_unthemed_batch` does; the dry run's
   `themes.unthemed_embedded` counts the same set) to its nearest theme
   centroid. Themes over
   W1's member cap (default 2,000) are REPORTED under `themes.over_cap`.
   Without the off-box hook (below) they are never split here: the theme
   split stays W1's operator-run tool (`scripts/theme_cap_split.py`, off-box
   compute). With the hook and `--theme-cap-split`, they are split through
   it before the maps are read (`themes.split`).
2. **Maps.** For every map with a finished run (or each `--map`), in one
   REPEATABLE READ snapshot:
   - updates each theme's "by meaning" tree (a new claim joins the leaf with
     the nearest centroid) and "by links" tree (W5b mirrors, new links join
     their neighbours' leaf), a leaf over the 100-node cap or the contract's
     1,024 edges split on the box by W3's fallback split (`resplit_leaves`);
     a leaf of ONE claim whose own agents and evidence carry more than 1,024
     edges among them cannot be split, so it keeps its heaviest 1,024 (each
     agent and evidence node keeps an edge to the claim) and the cut is
     reported under `leaf_edge_cap`;
   - builds real leaves (claims with their stored `truth_value` as the
     colour value, agents, evidence, W7 flow weights);
   - once every theme is final, builds the map's cross-group links: group
     `bundles` and `targets`, leaf `outgoing` (team-owned edges with no
     co-owner, or public ones, between claims the map draws; never a
     co-owned edge), each link listed from its source end only;
   - then lays out only the changed levels (W6, warm-started) and names only
     the changed groups (W8, through the Claude CLI, `--max-calls` per map).
3. **Writes** one new run per changed map, holding both hierarchies, then
   deletes the map's runs past the newest `--keep-runs` (default 3). A map
   whose levels and epochs are all unchanged gets no new run
   (`"status": "unchanged"`).

No UMAP or k-means runs on the box. A theme new to a map that does not fit
one leaf is `unbuilt` until an operator builds the map (below), or, with the
off-box hook, has its meaning tree computed off the box and is built the same
night (the map's `offbox`).

## The off-box hook (optional)

The clustering the box does not run can go through ONE command you provide,
the same off-box step as the operator tools, on ids and embeddings only
(backlog 691d283a). Off by default; turn it on with:

```bash
atlas_nightly --apply --offbox-command /usr/local/lib/epigraph/offbox \
  --offbox-dir /var/lib/epigraph-atlas/offbox \
  [--theme-cap-split /opt/epigraph/scripts/theme_cap_split.py [--python python3]] \
  [--offbox-timeout-secs 3600]
```

The command is run as

```text
<command> theme-cap     <export-dir> <result-file>   # W1: split the over-cap themes
<command> atlas-meaning <export-dir> <result-file>   # W4: a new theme's meaning tree
```

and must write `<result-file>` and exit 0. `scripts/atlas_offbox_compute.py`
is a reference command that computes in place (it needs numpy, scikit-learn
and umap-learn, no database). On a box without UMAP, point
`--offbox-command` at a wrapper that copies `<export-dir>` to a compute host,
runs `atlas_offbox_compute.py` there with the same three arguments, and
copies the result back.

What the box keeps:
- The command gets a CLEARED environment (`PATH`, `HOME`, `LANG` only): never
  `DATABASE_URL`, `MAINTENANCE_DATABASE_URL` or another credential. Give the
  wrapper what it needs (an SSH key, a host name) through its own files.
- The export (claim ids and embeddings; for `atlas-meaning` also per-theme
  attachment integers; no text, no agent or evidence id, no tenancy) is
  written owner-only under `--offbox-dir`, which must exist and be
  owner-only (`chmod 700`), and is DELETED as soon as the command returns,
  whatever it returned. An export a killed night left behind (the service's
  timeout, the OOM killer) is deleted at the next call; the call
  directories, results and manifests stay.
- The command runs in its own process group with no stdin and its stdout
  discarded; its stderr goes to the journal. At `--offbox-timeout-secs` the
  group is killed and the call counts as failed.
- A dry run (no `--apply`) exports nothing and runs nothing; it reports
  `themes.split.would_split` and each map's `offbox.would_compute`.

Every result is checked on the box as an operator's result is:
- `theme-cap` runs through `theme_cap_split.py offbox`: its export, the
  command, then its apply with every structural check (parts exactly the live
  members, under the cap, the result naming exactly the exported themes, one
  transaction). A theme whose members changed while the command ran (a claim
  arrived, left, or gained or lost an embedding) is skipped untouched and
  listed in `themes.split.report.skipped_changed`; the others are still
  split, and the skipped one stays over the cap for the next night. Parts
  that cover the members but break another check (a claim twice, a part over
  the cap) refuse the whole result. It is NOT checked against a reviewed plan (there is none
  without UMAP on the box): the manifest records `review: "offbox-command"`.
  The manifest stays in the call's directory under `--offbox-dir`
  (`themes.split.report.manifest`); undo a nightly split with
  `theme_cap_split.py reverse --manifest <it>`. Keep those manifests.
- `atlas-meaning`: the tree must be for this map and hierarchy, at most this
  cap, name exactly the exported themes, and pass W4's `check_tree` against
  the theme's members at build time (every id the minted one, the leaves
  exactly the members). A theme whose members changed since the export stays
  `unbuilt` with `offbox_tree_refused` and `offbox_members_changed: true`
  (the next night computes it again; this is not a failure). A tree whose
  leaves ARE the members but that the check still refuses (an id that is not
  the minted one, a bad shape: a compute host on another version) has
  `offbox_members_changed: false`, and the map's `offbox.status` is `failed`
  with the themes under `malformed`.
  The links tree of the new theme is then built on the box from it, as the
  nightly updates every other theme's.

A split's new parts are new themes on every map that draws them; when one
does not fit a leaf, the same night computes its meaning tree through the
hook, so the split does not hide them. A part filled exactly to the cap by
the unembedded placement (`theme_cap_core.unembedded_slots`) goes over it at
the next assignment, so expect such a theme to be split again on a later
night.

A failed call (the command exits non-zero, times out, or returns a result the
checks refuse; a member that changed during the call is not a failure) is
reported (`themes.split.status` or a map's
`offbox.status` is `failed`, with the error), the night still builds and
writes every map it can, and the exit status is 1 so the alert fires. The
whole night, off-box calls included, must fit the service's
`TimeoutStartSec=` window; raise it when you enable the hook.

### The summary

The binary prints one JSON summary. Per map, `status` is `written`,
`unchanged`, `dry_run`, `skipped` (no finished run yet), `superseded` (a
newer run was published while the night ran; nothing was written) or
`failed`. Also per map:
- `themes.built` (per theme: members, added, removed, leaves, resplit leaves,
  linked, mirrors), `themes.carried`, `themes.dropped`, `themes.unbuilt`;
- `unembedded_members` (current themed claims the map may draw with no
  embedding, in every theme, also one with no embedded member: in no leaf);
- `links` (the cross-group links: `links` read, and what the contract caps
  cut: `dropped_targets`, `dropped_bundles`, `dropped_outgoing`,
  `dropped_links`; also stored in the run's `params`). A cut keeps the
  heaviest and never fails the night;
- `leaf_edge_cap` (`capped_leaves`, `dropped_edges`: the one-claim leaves
  over the contract's 1,024 edges and the edges they left out; also per
  theme in `themes.built[].stats` and in the run's `params`). Like the link
  caps it keeps the heaviest and never fails the night: the claim and every
  one of its agents and evidence rows are still drawn, only the weakest
  edges among them are not;
- `layout.relaid` (the levels laid out again) and `naming.renamed` (the
  levels whose naming input changed), `naming.report.calls`;
- `offbox` (only with the hook, when the map had an `unbuilt` theme):
  `status` `computed` (with `still_unbuilt`), `failed` (with `error`, and
  `malformed` when the trees came back but were refused) or `dry_run`
  (`would_compute`).

At the top level, `themes.split` (only with `--theme-cap-split`, when a theme
is over the cap): `status` `applied` or `nothing to split` (the script's own
status; its `report`, with `skipped_changed`, and `still_over_cap` after it),
`failed` (with `error`) or `dry_run` (`would_split`).

A theme whose update FAILS does not fail the night. A leaf over the edge
limit no longer fails one (above: several claims are split, one claim is
capped). The known remaining cause is a stored edge whose relationship name
the contract refuses (it allows letters, digits and `_`, at most 32
characters, starting with a letter; `edges` takes any non-empty name and the
leaf serves the stored one lower-cased). The theme is:
- **carried**: the previous run's levels of that theme are kept, both
  hierarchies, when every node and edge of every carried leaf is still in
  that leaf assembled from what the map may draw now (claims that arrived
  since are simply missing from it); or
- **dropped** from the run otherwise (a claim, agent, evidence row or edge
  of it left the map's audience: carrying it would leak it).

Both list the error. For a refused relationship name an operator build does
NOT clear it (the build would store the same leaf again): file the error
(it names the level and the edge). Any other error: rebuild the map (below) and
file the error.

Exit codes: 0 when every map was written, unchanged, skipped or a dry run;
1 when a map failed, a configured off-box call failed, or the night refused
to start (the timer's alert fires);
2 for an argument error; 75 when another copy (the timer's, or an
operator's) holds the nightly lock: NOTHING ran, it prints `{"locked": true}`
and says so on stderr; retry once the other copy has finished. The service
unit counts 75 a success, so the timer firing beside a manual run does not
alert.

## Before the first night: the operator build

The nightly is incremental: it refreshes maps that already have a run. Build
each map once with W4 and W5's tools (export, off-box compute, one apply of
both results):

```bash
atlas_meaning export --map team:<group> --out <dir>      # on the box
python3 scripts/atlas_meaning_core.py compute --from <dir> --out meaning.json  # anywhere
atlas_links export --map team:<group> --meaning-from meaning.json --out <dir2>
python3 scripts/atlas_links_core.py compute --from <dir2> --out links.json
atlas_links apply --map team:<group> --meaning-from meaning.json --from links.json --apply
```

`atlas_links apply --apply` (and `atlas_meaning apply --apply`) holds the
map's publish lock for the whole build, so a night running meanwhile cannot
publish over the rebuild: it waits, finds the newer run and writes nothing
for that map (`"status": "superseded"`).

An operator build stores skeleton levels (claim nodes only, placeholder
positions, no names), and it is served as soon as it is applied: run
`atlas_nightly --apply --map <map>` right after it, so the map gets real
leaves, positions and names before anyone browses it.

Rebuild a map the same way whenever its summary keeps listing `unbuilt`,
`dropped` or `carried` themes, or many `resplit_leaves`: the nightly's
splits are W3's id-order fallback, not a clustering. A standalone
`atlas_meaning apply --apply` is refused once a map has a links run (it
would hide it).

## After a theme-cap split (W1): required rebuilds

`scripts/theme_cap_split.py apply` moves claims from each split parent to
new parts. The rows derived from theme membership are built per run, so
nothing in the apply updates them, and they stay wrong until rebuilt
(backlog 30633061):
- **graph neighbourhoods** (`graph_neighborhoods`, served from the newest
  clustering run): the moved claims are still filed under the parent's
  neighbourhoods, and the parts have none;
- **the shared Atlas layout** (`atlas_layout_themes`, the newest layout run):
  the parts have no position (the run reads `stale`) and the parent's sits
  where its whole-theme centroid was.

The rebuild is a new run of each: the maintenance role may not delete one
theme's neighbourhood rows (they leave only with their run), so a split's
neighbourhoods are rebuilt by a new `ClusterGraph` run, which covers every
theme. Apply prints, and its manifest records, `touched_theme_ids` (every
parent and every new part) and `rebuild_next`. Run these, in order, right
after the apply, with the maintenance DSN in the environment (as in "Dry
run" below):

```bash
enqueue_job --job '{"ClusterGraph":{"resolution":1.0,"retain_runs":3}}' --unique
drain_jobs                                            # or wait for epigraph-jobs-drain.timer
python3 scripts/label_themes_llm.py --neighborhoods   # the new run's rows carry placeholder labels
atlas_layout --apply                                  # last: it records the newest clustering run
```

`--unique` enqueues nothing when a `ClusterGraph` is already pending; that
job runs after the apply, so it rebuilds the split too. One that was already
RUNNING when the apply committed read the old membership: enqueue another
once it has finished. Check the drain's report for the job's `run_id` and that
every id in `touched_theme_ids` has neighbourhoods in it
(`SELECT theme_id, count(*) FROM graph_neighborhoods WHERE run_id = '<run_id>'
AND theme_id = ANY('{<ids>}'::uuid[]) GROUP BY 1`; a part with no current
member that is a leaf in the decomposition tree has none, which is correct).

After `theme_cap_split.py reverse --manifest M`, run the same steps: the
parts are gone, and the parent's neighbourhoods and position in the newest
runs still lack the claims it got back.

The nightly sees the parts as new themes of every map that draws them: one
that does not fit a single leaf is `unbuilt` until an operator builds the map
(above).

## Dry run

Every command runs with the maintenance DSN in the environment, never on the
command line (argv is visible to every local user through `ps`):

```bash
set -a; . /etc/epigraph/atlas-nightly.env; set +a   # DATABASE_URL, MAINTENANCE_DATABASE_URL
atlas_nightly                     # every map; nothing assigned, written or named
atlas_nightly --map public        # one map
```

A dry run calls no model. Its per-map `would_write` says whether `--apply`
would write a run, and `naming.report.deferred` how many levels it would
name.

## Apply

```bash
atlas_nightly --apply --max-calls 400
```

The first night after an operator build names every level (each is new to
the naming record), so expect `--max-calls` to defer some; the next nights
name the rest. Later nights call the model only for changed groups.

## Rollback

Stop the timer first, or the next night rebuilds from the restored run and
writes the same change again:

```bash
sudo systemctl stop epigraph-atlas-nightly.timer
```

A night writes one `atlas_map_runs` row per changed map (`run_id` in the
summary). To undo it, delete that row as the maintenance login; its levels go
with it (`ON DELETE CASCADE`) and the previous finished run is served again:

```sql
DELETE FROM atlas_map_runs WHERE id = '<run_id>';
```

An operator build's run (`atlas_meaning apply --apply`, `atlas_links apply
--apply`) is undone with the binary's own `reverse` instead of a DELETE:
`atlas_meaning reverse --map M --run-id R` reports what it would delete and
which run is served after, and `--apply` deletes it and writes an audit row.
It refuses a nightly run, and an operator run a later night was built from.

The pruned older runs are gone, so the rollback reaches back `--keep-runs - 1`
nights. The theme assignment of step 1 is not rolled back by this; it only
set `claims.theme_id` on claims that had none. Once the cause is fixed,
start the timer again (`sudo systemctl start epigraph-atlas-nightly.timer`).

## Enable the timer

The templates are in `deploy/systemd/`:
- `epigraph-atlas-nightly.service`: a oneshot running
  `atlas_nightly --apply --max-calls 400 --keep-runs 3`, three-hour window,
  `OnFailure=` the alert;
- `epigraph-atlas-nightly.timer`: 04:30 local, `Persistent=true`;
- `epigraph-atlas-nightly-alert@.service`: the alert, started with the failing
  unit's name.

1. Install the binary and pick the service user. It must be a user whose home
   holds the Claude CLI sign-in (the naming step runs `claude -p` as that
   user, from a private directory under its home), so do not add
   `ProtectHome=`.
2. Write the environment file, 0600, root-owned: `DATABASE_URL` and
   `MAINTENANCE_DATABASE_URL` (the maintenance login; the binary refuses to
   run without it).
3. Edit the placeholders in the three units: the binary path, `User=` and
   `Group=`, the environment file, and the alert's `ExecStart` (a command
   that sends the unit name and `journalctl -u <unit> -n 50` through a path
   whose delivery you have verified).
4. Check them: `systemd-analyze verify <the three files>`.
5. Install and enable:
   ```bash
   sudo install -m 0644 epigraph-atlas-nightly.service epigraph-atlas-nightly.timer \
        'epigraph-atlas-nightly-alert@.service' /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl start epigraph-atlas-nightly.service   # one night now; read the journal
   sudo systemctl enable --now epigraph-atlas-nightly.timer
   ```
6. Do NOT re-enable the old theme-maintenance task: this job replaces it.

Watch the first nights: `journalctl -u epigraph-atlas-nightly -n 200`. Test
the alert once by starting the alert unit by hand.
