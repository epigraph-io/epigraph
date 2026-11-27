"""DB arm: screen_public_claims.py over a throwaway fixture database (backlog 85fb918a).

Seeds claims on the superuser connection, runs the script as an operator
would (a subprocess with --database-url, on the test maintenance login of
tests/db_roles.py), and reads its JSONL and ids file back:

  * each public, current fixture claim gets exactly its expected reasons, and
    a clean one is absent;
  * a group-visibility hit and a superseded (not current) public hit are
    absent: only what guests could read is screened;
  * no fixture claim's text appears anywhere the script writes;
  * the ids file is the restrict-claims format (one UUID per line, `#`
    comments).

The shared `_test` database may hold other public claims, so the assertions
are over the fixture's ids. Every name and marker is invented.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import uuid

import pytest

REQUIRE_DB = os.environ.get("EPIGRAPH_PYTEST_REQUIRE_DB") == "1"


def _unavailable(reason: str, **kw):
    if REQUIRE_DB:
        pytest.fail(f"EPIGRAPH_PYTEST_REQUIRE_DB=1 but {reason}", pytrace=False)
    pytest.skip(reason, **kw)


try:
    import psycopg2
except ImportError:
    _unavailable("psycopg2 is not installed", allow_module_level=True)

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "screen_public_claims.py"
sys.path.insert(0, str(REPO))

from tests import db_roles  # noqa: E402

TEST_DSN = os.environ.get("DEDUP_TEST_DATABASE_URL", "")
if not (TEST_DSN.rstrip("/").endswith("_test") or "/_sqlx_test" in TEST_DSN):
    _unavailable(
        "DEDUP_TEST_DATABASE_URL must name a database ending in `_test`",
        allow_module_level=True,
    )

# name -> (content, labels, visibility, is_current, expected reasons or None
# when the claim must not appear at all)
FIXTURES = {
    "quote": ("S1 " + "z" * 320, [], "public", True, ["long_content"]),
    "uuid": ("S2 see 3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b", [], "public", True, ["uuid_like_id"]),
    "host_and_mail": ("S3 mail ops@build-01.internal", [], "public", True,
                      ["internal_hostname", "email_address"]),
    "group_label": ("S4 an ordinary sentence", ["team:nightjar working party"], "public", True,
                    ["private_group_name"]),
    "street": ("S5 moved to 221 Baker Street", [], "public", True, ["street_address"]),
    "clean": ("S6 soil carbon rose between 1990-2000", ["topic:soil"], "public", True, None),
    "private_hit": ("S7 call (555) 123-4567", [], "group", True, None),
    "superseded_hit": ("S8 call (555) 765-4321", [], "public", False, None),
}


@pytest.fixture
def world(tmp_path):
    try:
        # MAINTENANCE-DSN-EXEMPT: a test fixture on the CI-provisioned disposable
        # `_test` database (guarded above), not an operator script.
        conn = psycopg2.connect(TEST_DSN)
    except Exception as e:  # noqa: BLE001
        _unavailable(f"test DB unavailable: {e}")
    conn.autocommit = True
    cur = conn.cursor()
    agent = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO agents (id, public_key, agent_type) VALUES (%s, %s, 'system')",
        (agent, psycopg2.Binary(os.urandom(32))),
    )
    cur.execute(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) "
        "VALUES (%s, 'did:epigraph:personal:' || %s, ''::bytea, 'personal', %s) RETURNING id::text",
        (f"screen-db:{agent}", agent, agent),
    )
    group = cur.fetchone()[0]
    token = uuid.uuid4().hex[:12]
    ids = {}
    for name, (content, labels, visibility, current, _) in FIXTURES.items():
        cid = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, "
            "                    visibility, owner_group_id, labels) "
            "VALUES (%s, %s, %s, 0.5, %s, %s, %s, %s, %s::text[])",
            (cid, f"{content} {token}", psycopg2.Binary(os.urandom(32)), agent, current,
             visibility, group, labels),
        )
        ids[name] = cid
    groups = tmp_path / "groups.txt"
    groups.write_text("# invented\nNightjar Working Party\n")
    yield {"ids": ids, "groups": groups, "tmp": tmp_path, "token": token}
    cur.execute("DELETE FROM claims WHERE id = ANY(%s::uuid[])", (list(ids.values()),))
    conn.close()


def test_the_screen_emits_the_expected_jsonl_for_the_fixture(world):
    out = world["tmp"] / "hits.jsonl"
    ids_file = world["tmp"] / "candidates.txt"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--database-url", db_roles.script_dsn(TEST_DSN),
         "--private-groups", str(world["groups"]), "--out", str(out),
         "--claims-file-out", str(ids_file)],
        capture_output=True, text=True, timeout=300, cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr[-3000:]

    by_id = {}
    for line in out.read_text().splitlines():
        row = json.loads(line)
        assert set(row) == {"claim_id", "reasons"}, row
        by_id[row["claim_id"]] = row["reasons"]
    mine = {cid: by_id[cid] for cid in world["ids"].values() if cid in by_id}
    expected = {world["ids"][n]: f[4] for n, f in FIXTURES.items() if f[4] is not None}
    assert mine == expected, (mine, expected)

    listed = [ln for ln in ids_file.read_text().splitlines() if ln and not ln.startswith("#")]
    for ln in listed:
        uuid.UUID(ln)
    assert set(expected) <= set(listed)
    for name in ("clean", "private_hit", "superseded_hit"):
        assert world["ids"][name] not in listed, name

    summary = [ln for ln in proc.stderr.splitlines() if ln.startswith("summary: ")]
    assert len(summary) == 1, proc.stderr
    counts = json.loads(summary[0][len("summary: "):])
    assert counts["flagged"] >= len(expected) and counts["scanned"] > counts["flagged"]
    assert counts["by_reason"]["private_group_name"] >= 1

    written = proc.stdout + proc.stderr + out.read_text() + ids_file.read_text()
    assert world["token"] not in written, "no claim's text is printed"
    for content, *_ in FIXTURES.values():
        assert content.split(" ", 1)[1][:20] not in written, content
