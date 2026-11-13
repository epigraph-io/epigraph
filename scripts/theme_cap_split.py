#!/usr/bin/env python3
"""Split every theme over the claim cap, reversibly (Atlas W1, backlog 8c4aefda).

No theme should hold more than about 2,000 claims (design 2026-11-12 §2). Each
theme over the cap is split, by UMAP over its members' embeddings and then
k-means, recursively until every part is at or under the cap
(`theme_cap_core.split_to_cap`). The existing splitters fall short of this:
`split_theme.py` cuts one theme in two, `maintain_themes.py` splits only
high-variance themes, and `theme_pipeline.py grow` caps at 8,000.

Commands:
  plan      DRY RUN. Lists every theme over the cap with its proposed part
            sizes and writes the parts (claim ids only) to a result file.
            Writes nothing to the database.
  export    Writes each over-cap theme's member ids and embeddings to a
            directory (`<theme_id>.npz` + `export.json`), for `compute`
            elsewhere. No claim text is exported.
  compute   Runs the split over an export directory. Needs no database and
            no DB driver: this is the step that may run off the box.
  apply     Writes a result file (`--from`, from `plan` or `compute`) in ONE
            transaction, and writes a manifest that `reverse` restores from.
  reverse   Restores exactly what a manifest's apply changed.

What apply writes, per theme:
  * The largest part keeps the theme's id; every other part becomes a new
    claim_themes row and its members move to it (`claims.theme_id`).
  * `claim_count` and `centroid` are recomputed from each part's members, as
    split_theme.py does (`centroid_3072` too when the parent had one).
  * Lineage in `properties`: the parent's properties are copied, and
    `split_of`, `split_part`, `split_path`, `split_run`, `split_method` and
    `split_cap` are set. `split_path` extends the parent's, so
    `(cluster_run_id, cluster_id, split_path)` stays a unique key when a part
    of an earlier split is split again; the earlier `split_of`/`split_part`
    are kept in `split_history`.
  * Names are NOT derived from claim text. Each part is labelled
    `<parent label> · part <path>` (a placeholder parent becomes
    "Unnamed theme"), the description is cleared, and `needs_naming: true`
    marks it for the Atlas group naming (W8). The label is kept short and
    off label_themes_llm's placeholder patterns, so that script's default run,
    which samples member text, does not rename it.
  * Refused, with nothing written, when the result no longer matches the live
    membership (claims assigned or moved since the plan), or when a part would
    end over the cap once members without an embedding (which stay with the
    kept part) are counted.

Member text: nothing here reads, prints or stores claim content, so the
bug-report intake rule (`theme_lib.not_intake_owned`, which keeps intake text
out of stored labels) has nothing to filter. Intake-owned members move with
their part like any other member, as membership is outside that rule.

Database role: run as the MAINTENANCE role (MAINTENANCE_DATABASE_URL, a login
in the `epigraph_maintenance` role). `claims` has forced row-level security,
so an application-role connection sees and moves only a subset of each theme
and would report success. This script refuses a DSN whose user is the
application role, and refuses a session that row-level security on `claims`
applies to (not a superuser or BYPASSRLS role, and the database's own
`epigraph_bypass()` is false).

After an apply, Atlas layouts (`atlas_layout_themes`) and graph neighbourhoods
of a split theme are stale until rebuilt. `reverse` deletes the new parts'
rows, and rows that reference them cascade.

Usage:
    MAINTENANCE_DATABASE_URL=... python3 scripts/theme_cap_split.py plan --out plan.json
    MAINTENANCE_DATABASE_URL=... python3 scripts/theme_cap_split.py apply --from plan.json \\
        --manifest manifest.json
    MAINTENANCE_DATABASE_URL=... python3 scripts/theme_cap_split.py reverse --manifest manifest.json

    # Off-box compute: export on the box, compute anywhere, apply on the box.
    MAINTENANCE_DATABASE_URL=... python3 scripts/theme_cap_split.py export --out export-dir/
    python3 scripts/theme_cap_split.py compute --from export-dir/ --out result.json
    MAINTENANCE_DATABASE_URL=... python3 scripts/theme_cap_split.py apply --from result.json \\
        --manifest manifest.json
"""
import argparse
import datetime
import json
import os
import pathlib
import re
import sys
import urllib.parse
import uuid

import theme_cap_core as core

APPLICATION_ROLE = "epigraph_app"
MANIFEST_FORMAT = "theme-cap-manifest/1"
SPLIT_METHOD = "umap-kmeans-cap"
UNNAMED = "Unnamed theme"
# label_themes_llm.is_placeholder_label treats a label of 60+ characters as a
# placeholder and renames it from member text.
LABEL_MAX = 59
_PART_SUFFIX = re.compile(r"\s*·\s*part\s+[0-9.]+$")


# ── names ───────────────────────────────────────────────────────────────────

def part_label(parent_label, split_path):
    """`<parent label> · part <path>`, under LABEL_MAX characters.

    The parent's own part suffix is dropped (the path already carries it). A
    parent that is itself a placeholder becomes "Unnamed theme", so the result
    never matches a placeholder pattern."""
    root = _PART_SUFFIX.sub("", (parent_label or "").strip()).strip()
    if (not root or root.startswith(("auto-", "cluster-"))
            or "is defined as" in root or "defined as:" in root):
        root = UNNAMED
    suffix = " · part " + ".".join(str(p + 1) for p in split_path)
    room = LABEL_MAX - len(suffix)
    if len(root) > room:
        root = root[:max(1, room - 1)].rstrip() + "…"
    return root + suffix


# ── role guard and connection ───────────────────────────────────────────────

def _dsn_user(dsn):
    if not dsn:
        return None
    try:
        parts = urllib.parse.urlsplit(dsn)
    except ValueError:
        parts = None
    if parts is not None and parts.scheme in ("postgres", "postgresql"):
        try:
            return parts.username
        except ValueError:
            return None
    m = re.search(r"(?:^|\s)user\s*=\s*'?([^'\s]+)", dsn)
    return m.group(1) if m else None


def refuse_application_role(dsn):
    """Exit when the DSN logs in as the application role (forced RLS: a subset)."""
    if _dsn_user(dsn) == APPLICATION_ROLE:
        sys.exit(
            f"refusing: the DSN logs in as {APPLICATION_ROLE}. claims has forced row-level "
            "security, so this role sees only a subset of each theme. Run as the maintenance "
            "role: set MAINTENANCE_DATABASE_URL."
        )


def require_maintenance_session(conn):
    """Exit unless this session reads `claims` whole.

    It does when `claims` has no row-level security, when the session role is
    a superuser or BYPASSRLS, or when the database's own `epigraph_bypass()`
    (membership of `epigraph_maintenance`) holds. The rule is the database's,
    asked of the database, rather than a Python restatement of it."""
    with conn.cursor() as cur:
        cur.execute("SELECT c.relrowsecurity, r.rolsuper OR r.rolbypassrls, "
                    "       to_regprocedure('public.epigraph_bypass()') IS NOT NULL "
                    "FROM pg_class c, pg_roles r "
                    "WHERE c.oid = 'public.claims'::regclass AND r.rolname = session_user")
        rls, privileged, has_fn = cur.fetchone()
        bypass = False
        if rls and not privileged and has_fn:
            cur.execute("SELECT public.epigraph_bypass()")
            bypass = cur.fetchone()[0]
    conn.rollback()
    if rls and not privileged and not bypass:
        sys.exit("refusing: this session does not bypass row-level security on claims "
                 "(epigraph_bypass() is false), so it would read and move only a subset. "
                 "Run as the maintenance role: set MAINTENANCE_DATABASE_URL.")


def connect(database_url=None):
    import theme_lib  # lazy: compute must run without a DB driver

    dsn = database_url or theme_lib.maintenance_dsn()
    refuse_application_role(dsn)
    conn = theme_lib.connect(dsn)
    theme_lib.set_statement_timeout(conn, ms=900000)
    require_maintenance_session(conn)
    return conn


# ── reads ───────────────────────────────────────────────────────────────────

def over_cap_themes(conn, cap, theme_ids=None):
    """[(theme_id, members, embedded)] for every theme with more than `cap`
    members, counted live (not from the stored claim_count)."""
    sql = ("SELECT theme_id::text, count(*), count(*) FILTER (WHERE embedding IS NOT NULL) "
           "FROM claims WHERE theme_id IS NOT NULL {} "
           "GROUP BY theme_id HAVING count(*) > %s ORDER BY theme_id")
    with conn.cursor() as cur:
        if theme_ids:
            cur.execute(sql.format("AND theme_id = ANY(%s::uuid[])"), (list(theme_ids), cap))
        else:
            cur.execute(sql.format(""), (cap,))
        return [(t, int(n), int(e)) for t, n, e in cur.fetchall()]


def load_members(conn, theme_id):
    """(ids, embeddings) of a theme's embedded members, ids in id order."""
    import theme_lib

    with conn.cursor() as cur:
        cur.execute("SELECT id::text FROM claims WHERE theme_id = %s AND embedding IS NOT NULL "
                    "ORDER BY id", (theme_id,))
        ids = [r[0] for r in cur.fetchall()]
    return ids, theme_lib.load_embeddings_for_ids(conn, ids)


def theme_labels(conn, theme_ids):
    with conn.cursor() as cur:
        cur.execute("SELECT id::text, label FROM claim_themes WHERE id = ANY(%s::uuid[])",
                    (list(theme_ids),))
        return dict(cur.fetchall())


# ── plan / export / compute ─────────────────────────────────────────────────

def plan(conn, cap=core.DEFAULT_CAP, seed=core.DEFAULT_SEED, theme_ids=None):
    """Compute the split of every over-cap theme, writing nothing.

    Returns (result, report): the result document apply consumes, and one
    report row per theme with its proposed part sizes."""
    result = {"format": core.RESULT_FORMAT, "cap": cap, "seed": seed, "themes": []}
    report = []
    for theme_id, members, embedded in over_cap_themes(conn, cap, theme_ids):
        ids, x = load_members(conn, theme_id)
        parts = core.split_to_cap(ids, x, cap=cap, seed=seed)
        conn.rollback()  # end the read transaction between themes
        result["themes"].append({"theme_id": theme_id, "parts": parts})
        unembedded = members - embedded
        report.append({
            "theme_id": theme_id, "members": members, "embedded": embedded,
            "unembedded": unembedded, "part_sizes": [len(p) for p in parts],
            "kept_part_with_unembedded": (len(parts[0]) if parts else 0) + unembedded,
            "reaches_cap": bool(parts) and len(parts[0]) + unembedded <= cap,
        })
    return result, report


def export(conn, out_dir, cap=core.DEFAULT_CAP, seed=core.DEFAULT_SEED, theme_ids=None):
    """Write each over-cap theme's ids and embeddings to `out_dir`."""
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    index = {"format": core.EXPORT_FORMAT, "cap": cap, "seed": seed, "themes": []}
    for theme_id, members, embedded in over_cap_themes(conn, cap, theme_ids):
        ids, x = load_members(conn, theme_id)
        conn.rollback()
        core.write_theme_npz(out_dir / f"{theme_id}.npz", ids, x)
        index["themes"].append({"theme_id": theme_id, "members": members, "embedded": embedded})
    (out_dir / "export.json").write_text(json.dumps(index, indent=1))
    return index


def _write_json_new(path, doc):
    """Write `doc` to a NEW file and fsync it; never overwrite."""
    path = pathlib.Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
        f.flush()
        os.fsync(f.fileno())


# ── apply ───────────────────────────────────────────────────────────────────

def _commit(conn):
    """Seam for tests: the point after the manifest is durable."""
    conn.commit()


def _parent_path(props):
    if isinstance(props.get("split_path"), list):
        return list(props["split_path"])
    if "split_part" in props:  # a part of split_theme.py, which records no path
        return [props["split_part"]]
    return []


def _part_properties(props, parent_id, part, path, run, cap):
    history = list(props.get("split_history") or [])
    if "split_of" in props:
        history.append({k: props[k] for k in ("split_of", "split_part", "split_run")
                        if k in props})
    return dict(props, split_of=parent_id, split_part=part, split_path=path, split_run=run,
                split_method=SPLIT_METHOD, split_cap=cap, split_history=history,
                needs_naming=True)


def _recompute(cur, theme_id, with_3072):
    cur.execute(
        "UPDATE claim_themes ct SET centroid = s.c, claim_count = s.n "
        "FROM (SELECT avg(embedding)::vector(1536) c, count(*) n FROM claims "
        "      WHERE theme_id = %s AND embedding IS NOT NULL) s "
        "WHERE ct.id = %s",
        (theme_id, theme_id),
    )
    if with_3072:
        cur.execute(
            "UPDATE claim_themes ct SET centroid_3072 = s.c "
            "FROM (SELECT avg(embedding_3072)::vector(3072) c FROM claims "
            "      WHERE theme_id = %s AND embedding_3072 IS NOT NULL) s "
            "WHERE ct.id = %s",
            (theme_id, theme_id),
        )


def apply_result(conn, result, manifest_path):
    """Write a result document in one transaction; returns the manifest.

    The manifest is written and fsynced BEFORE the commit, so a committed
    apply always has one. A manifest whose apply did not commit reverses as a
    no-op."""
    if result.get("format") != core.RESULT_FORMAT:
        raise ValueError(f"not a {core.RESULT_FORMAT} result: {result.get('format')!r}")
    cap = int(result["cap"])
    run = str(uuid.uuid4())
    manifest = {"format": MANIFEST_FORMAT, "split_run": run, "cap": cap,
                "seed": result.get("seed"),
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "themes": []}
    touched = []
    try:
        with conn.cursor() as cur:
            for entry in result["themes"]:
                parent, parts = str(entry["theme_id"]), entry["parts"]
                cur.execute("SELECT to_jsonb(ct) FROM claim_themes ct WHERE id = %s FOR UPDATE",
                            (parent,))
                row = cur.fetchone()
                if row is None:
                    raise ValueError(f"theme {parent} no longer exists")
                snapshot = row[0]
                cur.execute("SELECT id::text FROM claims WHERE theme_id = %s "
                            "AND embedding IS NOT NULL", (parent,))
                members = [r[0] for r in cur.fetchall()]
                try:
                    core.validate_parts(members, parts, cap)
                except ValueError as e:
                    raise ValueError(f"theme {parent}: the result no longer matches its live "
                                     f"members ({e}); re-run plan") from None
                if len(parts) < 2:
                    continue
                props = snapshot.get("properties") or {}
                base = _parent_path(props)
                with_3072 = snapshot.get("centroid_3072") is not None
                new_parts = []
                for i, part_members in enumerate(parts):
                    path = base + [i]
                    label = part_label(snapshot.get("label"), path)
                    pprops = json.dumps(_part_properties(props, parent, i, path, run, cap))
                    if i == 0:
                        cur.execute("UPDATE claim_themes SET label = %s, description = '', "
                                    "properties = %s::jsonb, updated_at = now() WHERE id = %s",
                                    (label, pprops, parent))
                        touched.append((parent, with_3072))
                        continue
                    cur.execute("INSERT INTO claim_themes (label, description, claim_count, "
                                "centroid, properties) VALUES (%s, '', 0, NULL, %s::jsonb) "
                                "RETURNING id::text", (label, pprops))
                    target = cur.fetchone()[0]
                    cur.execute("UPDATE claims SET theme_id = %s "
                                "WHERE id = ANY(%s::uuid[]) AND theme_id = %s",
                                (target, part_members, parent))
                    if cur.rowcount != len(part_members):
                        raise RuntimeError(f"theme {parent}: moved {cur.rowcount} of "
                                           f"{len(part_members)} members; refusing")
                    new_parts.append({"theme_id": target, "claim_ids": part_members})
                    touched.append((target, with_3072))
                cur.execute("SELECT id::text FROM claims WHERE theme_id = %s ORDER BY id",
                            (parent,))
                kept = [r[0] for r in cur.fetchall()]
                manifest["themes"].append({"parent_id": parent, "parent_row": snapshot,
                                           "kept_claim_ids": kept, "new_parts": new_parts})
            for theme_id, with_3072 in touched:
                _recompute(cur, theme_id, with_3072)
            if touched:
                cur.execute("SELECT theme_id::text, count(*) FROM claims "
                            "WHERE theme_id = ANY(%s::uuid[]) GROUP BY theme_id "
                            "HAVING count(*) > %s ORDER BY 1",
                            ([t for t, _ in touched], cap))
                over = cur.fetchall()
                if over:
                    raise ValueError(f"parts would end over the cap of {cap} (members without "
                                     f"an embedding stay with the kept part): {over}")
        if not manifest["themes"]:
            conn.rollback()
            return manifest
        _write_json_new(manifest_path, manifest)
        _commit(conn)
    except BaseException:
        conn.rollback()
        raise
    return manifest


# ── reverse ─────────────────────────────────────────────────────────────────

def _restorable_columns(cur):
    cur.execute("SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = 'claim_themes' "
                "AND column_name <> 'id' AND is_generated = 'NEVER' ORDER BY ordinal_position")
    return [r[0] for r in cur.fetchall()]


def _members(cur, theme_id):
    cur.execute("SELECT id::text FROM claims WHERE theme_id = %s", (theme_id,))
    return {r[0] for r in cur.fetchall()}


def reverse_manifest(conn, manifest, allow_drift=False):
    """Undo an apply in one transaction. Returns one status row per theme.

    Refuses when membership changed since the apply (a claim assigned to,
    moved out of, or reassigned between the parts), unless `allow_drift`, in
    which case every current member of a new part goes back to the parent and
    the parent's count and centroid are recomputed instead of restored."""
    from psycopg2 import sql

    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"not a {MANIFEST_FORMAT} manifest: {manifest.get('format')!r}")
    status = []
    try:
        with conn.cursor() as cur:
            cols = _restorable_columns(cur)
            restore = sql.SQL(
                "UPDATE claim_themes t SET ({cols}) = (SELECT {rcols} FROM "
                "jsonb_populate_record(NULL::claim_themes, %s::jsonb) r) WHERE t.id = %s"
            ).format(cols=sql.SQL(", ").join(map(sql.Identifier, cols)),
                     rcols=sql.SQL(", ").join(sql.SQL("r.") + sql.Identifier(c) for c in cols))
            for t in reversed(manifest["themes"]):
                parent = t["parent_id"]
                snapshot = json.dumps(t["parent_row"])
                new_ids = [p["theme_id"] for p in t["new_parts"]]
                cur.execute("SELECT id::text FROM claim_themes WHERE id = ANY(%s::uuid[])",
                            (new_ids,))
                present = {r[0] for r in cur.fetchall()}
                if not present:
                    cur.execute("SELECT to_jsonb(ct) = %s::jsonb FROM claim_themes ct "
                                "WHERE id = %s", (snapshot, parent))
                    same = cur.fetchone()
                    if same and same[0]:
                        status.append({"parent_id": parent, "status": "nothing to reverse"})
                        continue
                    raise ValueError(f"theme {parent}: its new parts are gone but it differs "
                                     "from its snapshot; refusing")
                if present != set(new_ids):
                    raise ValueError(f"theme {parent}: only {len(present)} of {len(new_ids)} "
                                     "new parts exist; refusing")
                drift = _members(cur, parent) != set(t["kept_claim_ids"]) or any(
                    _members(cur, p["theme_id"]) != set(p["claim_ids"]) for p in t["new_parts"])
                if drift and not allow_drift:
                    raise ValueError(f"theme {parent}: membership changed since the apply; "
                                     "refusing (--allow-drift moves every current member of "
                                     "the new parts back)")
                for p in t["new_parts"]:
                    cur.execute("UPDATE claims SET theme_id = %s WHERE theme_id = %s",
                                (parent, p["theme_id"]))
                cur.execute("DELETE FROM claim_themes WHERE id = ANY(%s::uuid[])", (new_ids,))
                cur.execute(restore, (snapshot, parent))
                if drift:
                    _recompute(cur, parent, t["parent_row"].get("centroid_3072") is not None)
                status.append({"parent_id": parent,
                               "status": "reversed with drift" if drift else "reversed"})
        _commit(conn)
    except BaseException:
        conn.rollback()
        raise
    return status


# ── CLI ─────────────────────────────────────────────────────────────────────

def _stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Split every theme over the claim cap (Atlas W1). Run as the maintenance "
                    "role (MAINTENANCE_DATABASE_URL); see the module docstring.")
    sub = p.add_subparsers(dest="command", required=True)

    def db_args(sp):
        sp.add_argument("--database-url", default=None,
                        help="default: MAINTENANCE_DATABASE_URL, then DATABASE_URL")

    def select_args(sp):
        sp.add_argument("--cap", type=int, default=core.DEFAULT_CAP)
        sp.add_argument("--seed", type=int, default=core.DEFAULT_SEED)
        sp.add_argument("--theme-id", action="append", default=None,
                        help="limit to this theme (repeatable)")

    sp = sub.add_parser("plan", help="dry run: list over-cap themes and proposed parts")
    db_args(sp)
    select_args(sp)
    sp.add_argument("--out", default=None, help="result file (default theme-cap-plan-<UTC>.json)")

    sp = sub.add_parser("export", help="write ids + embeddings of over-cap themes")
    db_args(sp)
    select_args(sp)
    sp.add_argument("--out", required=True, help="export directory")

    sp = sub.add_parser("compute", help="split an export directory (no database)")
    sp.add_argument("--from", dest="src", required=True, help="export directory")
    sp.add_argument("--out", required=True, help="result file")
    sp.add_argument("--cap", type=int, default=None, help="default: the export's cap")
    sp.add_argument("--seed", type=int, default=None, help="default: the export's seed")

    sp = sub.add_parser("apply", help="write a result file; writes a manifest")
    db_args(sp)
    sp.add_argument("--from", dest="src", required=True, help="result file from plan or compute")
    sp.add_argument("--manifest", default=None,
                    help="manifest to create (default theme-cap-manifest-<UTC>.json)")

    sp = sub.add_parser("reverse", help="restore what an apply changed")
    db_args(sp)
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--allow-drift", action="store_true")

    args = p.parse_args(argv)

    if args.command == "compute":
        result = core.compute_export_dir(args.src, cap=args.cap, seed=args.seed)
        _write_json_new(args.out, result)
        print(json.dumps({"status": "computed", "result_file": args.out, "cap": result["cap"],
                          "themes": [{"theme_id": t["theme_id"],
                                      "part_sizes": [len(x) for x in t["parts"]]}
                                     for t in result["themes"]]}))
        return 0

    conn = connect(args.database_url)
    try:
        if args.command == "plan":
            result, report = plan(conn, args.cap, args.seed, args.theme_id)
            out = args.out or f"theme-cap-plan-{_stamp()}.json"
            _write_json_new(out, result)
            labels = theme_labels(conn, [r["theme_id"] for r in report])
            for r in report:
                flag = "" if r["reaches_cap"] else "  NOT UNDER CAP (unembedded members)"
                print(f"  {r['theme_id']}  {r['members']:>6} -> {r['part_sizes']}"
                      f"  ({labels.get(r['theme_id'], '?')}){flag}", file=sys.stderr)
            print(json.dumps({"status": "dry-run", "cap": args.cap, "result_file": out,
                              "themes": report}))
        elif args.command == "export":
            index = export(conn, args.out, args.cap, args.seed, args.theme_id)
            size = sum(f.stat().st_size for f in pathlib.Path(args.out).iterdir())
            print(json.dumps({"status": "exported", "dir": args.out, "bytes": size,
                              "themes": index["themes"]}))
        elif args.command == "apply":
            result = json.loads(pathlib.Path(args.src).read_text())
            mpath = args.manifest or f"theme-cap-manifest-{_stamp()}.json"
            manifest = apply_result(conn, result, mpath)
            print(json.dumps({"status": "applied" if manifest["themes"] else "nothing to split",
                              "manifest": mpath if manifest["themes"] else None,
                              "split_run": manifest["split_run"],
                              "themes": [{"parent_id": t["parent_id"],
                                          "kept": len(t["kept_claim_ids"]),
                                          "new_parts": [{"theme_id": n["theme_id"],
                                                         "claims": len(n["claim_ids"])}
                                                        for n in t["new_parts"]]}
                                         for t in manifest["themes"]]}))
        elif args.command == "reverse":
            manifest = json.loads(pathlib.Path(args.manifest).read_text())
            print(json.dumps({"status": "reversed",
                              "themes": reverse_manifest(conn, manifest, args.allow_drift)}))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
