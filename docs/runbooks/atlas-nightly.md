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
   W1's member cap (default 2,000) are REPORTED under `themes.over_cap`, never
   split: the theme split stays W1's operator-run tool
   (`scripts/theme_cap_split.py`, off-box compute).
2. **Maps.** For every map with a finished run (or each `--map`), in one
   REPEATABLE READ snapshot:
   - updates each theme's "by meaning" tree (a new claim joins the leaf with
     the nearest centroid) and "by links" tree (W5b mirrors, new links join
     their neighbours' leaf), a leaf over the 100-node cap or the contract's
     1,024 edges split on the box by W3's fallback split (`resplit_leaves`);
   - builds real leaves (claims, agents, evidence, W7 flow weights);
   - then lays out only the changed levels (W6, warm-started) and names only
     the changed groups (W8, through the Claude CLI, `--max-calls` per map).
3. **Writes** one new run per changed map, holding both hierarchies, then
   deletes the map's runs past the newest `--keep-runs` (default 3). A map
   whose levels and epochs are all unchanged gets no new run
   (`"status": "unchanged"`).

No UMAP or k-means runs on the box. A theme new to a map that does not fit
one leaf is `unbuilt` until an operator builds the map (below).

### The summary

The binary prints one JSON summary. Per map, `status` is `written`,
`unchanged`, `dry_run`, `skipped` (no finished run yet), `superseded` (a
newer run was published while the night ran; nothing was written) or
`failed`. Also per map:
- `themes.built` (per theme: members, added, removed, leaves, resplit leaves,
  linked, mirrors), `themes.carried`, `themes.dropped`, `themes.unbuilt`;
- `unembedded_members` (current themed claims the map may draw with no
  embedding, in every theme, also one with no embedded member: in no leaf);
- `layout.relaid` (the levels laid out again) and `naming.renamed` (the
  levels whose naming input changed), `naming.report.calls`.

A theme whose update FAILS does not fail the night. The one known cause is
a single claim whose OWN agents and evidence carry more than the contract's
1,024 edges among them: no split can bring one claim under the limit. (A
leaf of several claims over 1,024 edges is split, not failed.) The theme
is:
- **carried**: the previous run's levels of that theme are kept, both
  hierarchies, when every node and edge of every carried leaf is still in
  that leaf assembled from what the map may draw now (claims that arrived
  since are simply missing from it); or
- **dropped** from the run otherwise (a claim, agent, evidence row or edge
  of it left the map's audience: carrying it would leak it).

Both list the error. For the single-claim case an operator build does NOT
clear it (the build would store the same claim's leaf again): find the claim
in the error, and reduce the edges among its attachments (retract duplicate
or stale edges), after which the next night builds the theme. Any other
error: rebuild the map (below) and file the error.

Exit codes: 0 when every map was written, unchanged, skipped or a dry run;
1 when a map failed or the night refused to start (the timer's alert fires);
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
