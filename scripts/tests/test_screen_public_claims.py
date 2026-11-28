"""screen_public_claims.py flags public claims to review before guest reads (backlog 85fb918a).

Unit arm: the per-claim screen over fixtures, one per reason, plus clean
claims built from near misses (a year range, a DOI, a version string, a short
quote, exactly 300 characters, example.com), and the output contract: JSONL of
ids and reason codes only, never a claim's text, and no DSN in any message.
Every name and marker below is invented.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import screen_public_claims as spc  # noqa: E402

GROUPS = spc.compile_terms(["Nightjar Working Party", "ORCHID-7"])
MARKERS = spc.compile_terms(["acme-hidden-notes"])


def screen(content, labels=()):
    return spc.screen(content, list(labels), GROUPS, MARKERS)


LONG_QUOTE = '"' + " ".join(f"word{i}" for i in range(41)) + '"'

HITS = [
    # (1) verbatim text
    ("long_content", "x" * 301, ()),
    ("long_quoted_span", f"The author wrote {LONG_QUOTE} in the preface.", ()),
    ("long_quoted_span", "Curly: \u201c" + " ".join(["w"] * 41) + "\u201d.", ()),
    # (2) internal identifiers
    ("uuid_like_id", "See record 3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b for details.", ()),
    ("uuid_like_id", "A clean sentence.", ("ref:3F2B8C1E-9A4D-4E6F-8B2A-1C3D5E7F9A0B",)),
    ("internal_hostname", "The job ran on build-01.internal overnight.", ()),
    ("internal_hostname", "Served from 192.168.4.20 during the test.", ()),
    ("internal_hostname", "Served from 10.0.12.7 during the test.", ()),
    ("internal_hostname", "Served from 172.20.1.1 during the test.", ()),
    ("internal_hostname", "Reached at localhost:8080 only.", ()),
    # Assembled, so the repo's own sensitive-data check does not flag the
    # fixture: an EC2 private host name of an invented address.
    ("internal_hostname", "The node " + "ip-" + "-".join(["10", "1", "2", "3"]) + " went down.", ()),
    ("private_path", "Notes live in /home/alice/project/notes.md now.", ()),
    ("private_path", "Open file:///home/alice/project/notes.md in a browser.", ()),
    ("private_path", "Open file:///Users/bob/notes.md in a browser.", ()),
    ("private_path", "Copied from C:\\Users\\bob\\Desktop.", ()),
    ("private_path", "Read ~/drafts/plan.txt first.", ()),
    ("private_path", "Kept in team-private/runbooks for now.", ()),
    ("private_path", "A clean sentence.", ("src:ACME-Hidden-Notes/x",)),
    ("private_group_name", "Reviewed by the nightjar working party last week.", ()),
    ("private_group_name", "A clean sentence.", ("team:orchid-7",)),
    # (3) personal data
    ("email_address", "Contact jane.doe+lab@example.org for the data.", ()),
    ("phone_number", "Call (555) 123-4567 after noon.", ()),
    ("phone_number", "Call 555.123.4567 after noon.", ()),
    ("phone_number", "Call +44 20 7946 0958 after noon.", ()),
    ("street_address", "The lab moved to 221 Baker Street last year.", ()),
    ("street_address", "Mail it to 742 Evergreen Ave. by Friday.", ()),
    ("street_address", "Send it to P.O. Box 1234 instead.", ()),
]


@pytest.mark.parametrize("reason,content,labels", HITS, ids=[f"{h[0]}-{i}" for i, h in enumerate(HITS)])
def test_each_reason_fires_on_its_fixture(reason, content, labels):
    assert reason in screen(content, labels), (reason, content, labels)


CLEAN = [
    "Global mean temperature rose between 1990-2000 by about 0.2 C.",
    "The result is reported in doi:10.1000/xyz123 and replicated twice.",
    "The pipeline requires Python 3.12.3 and numpy 1.26.4.",
    'The authors call it "a modest gain" in the abstract.',
    "y" * 300,
    "Documentation is hosted at example.com and docs.example.org.",
    "A p-value of 0.05 at n = 1200 and +5 points on the scale.",
    "In 2020 Smith et al. measured 42 samples from 3 Main sites.",
    "Working parties and orchids are discussed in general terms.",
    "The @mention syntax and the user@ prefix are not addresses.",
    "Hash 3f2b8c1e is a short prefix, not a full identifier.",
    "The cluster mounts /srv/home/shared and /data/root/cache for every job.",
]


@pytest.mark.parametrize("content", CLEAN, ids=[f"clean-{i}" for i in range(len(CLEAN))])
def test_a_clean_claim_has_no_reason(content):
    assert screen(content, ["topic:climate", "kind:measurement"]) == []


def test_reasons_are_ordered_and_unique():
    content = "Email a@b.example or c@d.example from /home/carol/x at 10.1.1.1."
    got = screen(content)
    assert got == sorted(set(got), key=spc.REASONS.index)
    assert got == ["internal_hostname", "private_path", "email_address"]


def test_every_reason_has_a_fixture():
    assert {h[0] for h in HITS} == set(spc.REASONS)


def test_both_term_files_are_required(tmp_path, monkeypatch, capsys):
    """A run without --private-markers would screen no private directory name
    beyond the built-in `*-private/` shape, so the flag is required like
    --private-groups (an empty file is allowed)."""
    groups = tmp_path / "groups.txt"
    groups.write_text("")
    base = ["screen_public_claims.py", "--database-url", "postgres://reader@127.0.0.1:1/x_test"]
    for missing, argv in (
        ("--private-markers", base + ["--private-groups", str(groups)]),
        ("--private-groups", base + ["--private-markers", str(groups)]),
    ):
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as exc:
            spc.main()
        assert exc.value.code == 2
        assert missing in capsys.readouterr().err


def test_terms_are_read_from_a_file_and_never_built_in(tmp_path):
    f = tmp_path / "groups.txt"
    f.write_text("# private group names\n\nNightjar Working Party\n  ORCHID-7  \n")
    assert [t.pattern for t in spc.read_terms(str(f))] == [
        t.pattern for t in spc.compile_terms(["Nightjar Working Party", "ORCHID-7"])
    ]
    # Without a list, a group name is not a hit: nothing is hardcoded.
    assert "private_group_name" not in spc.screen(
        "Reviewed by the nightjar working party.", [], [], []
    )


class FakeCursor:
    def __init__(self, rows, log):
        self.rows, self.log, self.itersize = rows, log, None

    def execute(self, sql, params=None):
        self.log.append(sql)

    def __iter__(self):
        return iter(self.rows)

    def close(self):
        pass


class FakeConn:
    def __init__(self, rows):
        self.rows, self.log, self.session = rows, [], {}

    def set_session(self, **kw):
        self.session.update(kw)

    def cursor(self, name=None):
        self.log.append(("cursor", name))
        return FakeCursor(self.rows, self.log)

    def rollback(self):
        pass

    def close(self):
        pass


SECRET_TEXT = "Contact jane.doe@example.org at 221 Baker Street"
CLEAN_TEXT = "An unremarkable public claim about soil carbon."


def test_the_run_is_read_only_and_prints_ids_and_reasons_only():
    rows = [
        ("00000000-0000-0000-0000-00000000000a", SECRET_TEXT, ["topic:x"], True),
        ("00000000-0000-0000-0000-00000000000b", CLEAN_TEXT, None, True),
        ("00000000-0000-0000-0000-00000000000c", "Old version: call (555) 123-4567.", None, False),
    ]
    conn = FakeConn(rows)
    out, err, ids = io.StringIO(), io.StringIO(), io.StringIO()
    counts = spc.run(conn, GROUPS, MARKERS, out, ids, err)

    assert conn.session.get("readonly") is True, "the session is read-only"
    assert any(isinstance(e, tuple) and e[1] for e in conn.log), "a server-side cursor"
    sql = next(e for e in conn.log if isinstance(e, str))
    where = sql.split("WHERE", 1)[1]
    assert "visibility = 'public'" in where
    # The guest card reads a claim by id whatever its is_current, so a
    # superseded public claim is screened too.
    assert "is_current" not in where, where

    lines = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert lines == [
        {"claim_id": rows[0][0], "is_current": True,
         "reasons": ["email_address", "street_address"]},
        {"claim_id": rows[2][0], "is_current": False, "reasons": ["phone_number"]},
    ]
    assert ids.getvalue().splitlines()[1:] == [rows[0][0], rows[2][0]]
    assert counts["scanned"] == 3 and counts["flagged"] == 2
    assert counts["by_reason"]["email_address"] == 1
    assert counts["by_reason"]["long_content"] == 0
    everything = out.getvalue() + ids.getvalue() + err.getvalue()
    for text in (SECRET_TEXT, CLEAN_TEXT, "jane.doe", "Baker", "soil carbon"):
        assert text not in everything, text


def test_a_connection_failure_never_prints_the_dsn(monkeypatch, capsys, tmp_path):
    groups = tmp_path / "groups.txt"
    groups.write_text("")
    sentinel = "pw-sentinel-85fb918a"
    dsn = f"postgres://reader:{sentinel}@127.0.0.1:1/nothing_test"

    def _refuse(*_a, **_kw):
        raise spc.psycopg2.OperationalError(f"connection to {dsn} failed")

    monkeypatch.setattr(spc.psycopg2, "connect", _refuse)
    monkeypatch.setattr(sys, "argv", ["screen_public_claims.py", "--database-url", dsn,
                                      "--private-groups", str(groups),
                                      "--private-markers", str(groups)])
    assert spc.main() == 2
    captured = capsys.readouterr()
    assert sentinel not in captured.out + captured.err
    assert "reader" not in captured.out + captured.err
    assert "could not connect" in captured.err
