"""docs/conventions/no-longer-in-force.md names, per table, how a row stops
being in force, and every row is checked against the tree (backlog 64eeca4e).

Each table row must cite the migration that defines its mechanism (a file that
exists and spells the column) and a canonical reader filter (a symbol, and a
file that exists and contains it). A row whose migration or filter is renamed
away fails here instead of quietly pointing nowhere. Standard library only.
"""

import re
import unittest

from .convention_pins import REPO

PAGE = REPO / "docs" / "conventions" / "no-longer-in-force.md"

# The tables the page must cover, by the first cell of their row.
REQUIRED_ROWS = (
    "`claims`",
    "`claims` labelled `backlog`",
    "`mass_functions`",
    "`edges`",
    "`operator_links`",
    "`workflows`",
)

MIGRATION = re.compile(r"`(migrations/\d{3}_[a-z0-9_]+\.sql)` \(`([a-z_]+)\.([a-z_0-9]+)`")
FILTER = re.compile(r"`([A-Za-z_][A-Za-z0-9_:]*)` in `([^`]+)`")


def defines_column(sql, table, column):
    """True when `sql` creates `table` with `column`, or adds `column` to it."""
    tbl = r"(?:public\.)?" + re.escape(table)
    col = re.escape(column)
    create = re.search(r"CREATE TABLE (?:IF NOT EXISTS )?" + tbl + r" \((.*?)\n\);", sql, re.S)
    if create and re.search(r"^\s+" + col + r"\s", create.group(1), re.M):
        return True
    alter = r"ALTER TABLE (?:ONLY )?" + tbl + r"\s+ADD COLUMN (?:IF NOT EXISTS )?" + col + r"\s"
    return re.search(alter, sql) is not None


# A call that writes the workflows sentinel: `set_truth_value(<conn>, <id>, 0.05)`.
SENTINEL_WRITE = re.compile(r"WorkflowRepository::set_truth_value\([^;]*?\b0\.05\)", re.S)


def sentinel_writers():
    """Every non-test source file under crates/ that writes the 0.05 sentinel.

    Walks the tree (no git: the suite also runs on copies that are not
    checkouts) and ignores each file's `#[cfg(test)] mod tests` tail.
    """
    out = set()
    for path in sorted((REPO / "crates").glob("*/src/**/*.rs")):
        text = path.read_text(encoding="utf-8")
        cut = re.search(r"^#\[cfg\(test\)\]\s*\nmod tests\b", text, re.M)
        if cut:
            text = text[: cut.start()]
        if SENTINEL_WRITE.search(text):
            out.add(path.relative_to(REPO).as_posix())
    return out


def rows():
    """{first cell: [cells]} for every body row of the page's table."""
    out = {}
    for line in PAGE.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        out[cells[0]] = cells
    return out


class NoLongerInForcePage(unittest.TestCase):
    def test_page_exists(self):
        self.assertTrue(PAGE.is_file(), f"{PAGE.relative_to(REPO)} is missing")

    def test_every_required_table_has_a_row(self):
        self.assertTrue(PAGE.is_file())
        found = rows()
        for name in REQUIRED_ROWS:
            with self.subTest(table=name):
                self.assertIn(name, found)

    def test_every_row_cites_an_existing_defining_migration(self):
        self.assertTrue(PAGE.is_file())
        for name, cells in rows().items():
            with self.subTest(table=name):
                self.assertGreaterEqual(len(cells), 5, cells)
                m = MIGRATION.search(cells[2])
                self.assertIsNotNone(m, f"{name}: no `migrations/NNN_x.sql` (`table.column`) in {cells[2]!r}")
                path = REPO / m.group(1)
                self.assertTrue(path.is_file(), f"{name}: {m.group(1)} does not exist")
                self.assertTrue(
                    defines_column(path.read_text(encoding="utf-8"), m.group(2), m.group(3)),
                    f"{name}: {m.group(1)} does not define {m.group(2)}.{m.group(3)}",
                )

    def test_every_row_names_a_reader_filter_that_exists(self):
        self.assertTrue(PAGE.is_file())
        for name, cells in rows().items():
            with self.subTest(table=name):
                m = FILTER.search(cells[3])
                self.assertIsNotNone(m, f"{name}: no `symbol` in `file` in {cells[3]!r}")
                path = REPO / m.group(2)
                self.assertTrue(path.is_file(), f"{name}: {m.group(2)} does not exist")
                symbol = m.group(1).split("::")[-1]
                self.assertIn(symbol, path.read_text(encoding="utf-8"), f"{name}: {symbol} is not in {m.group(2)}")

    def test_workflow_row_is_marked_transitional(self):
        self.assertTrue(PAGE.is_file())
        row = " ".join(rows().get("`workflows`", []))
        self.assertIn("transitional", row.lower())
        self.assertIn("99f6dd92", row)

    def test_workflow_row_cites_every_sentinel_writer(self):
        # The sentinel's replacement (99f6dd92) uses this row as its list of
        # writers to convert; a writer missing here would keep writing 0.05.
        self.assertTrue(PAGE.is_file())
        row = " ".join(rows().get("`workflows`", []))
        writers = sentinel_writers()
        self.assertTrue(writers, "no sentinel writer found: has 99f6dd92 landed? update the row")
        for path in sorted(writers):
            with self.subTest(writer=path):
                self.assertIn(f"`{path}`", row)

    def test_retracted_bba_revives_only_through_the_audited_unretract(self):
        self.assertTrue(PAGE.is_file())
        row = " ".join(rows().get("`mass_functions`", []))
        self.assertIn("`epigraph_unretract_mass_function`", row)
        migration = (REPO / "migrations" / "184_mass_function_retract.sql").read_text(encoding="utf-8")
        self.assertIn("epigraph_unretract_mass_function", migration)


if __name__ == "__main__":
    unittest.main()
