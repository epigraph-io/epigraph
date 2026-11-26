"""The deploy guide describes the scripts' DSN rule as the code has it (backlog 62bdae04).

The scripts under scripts/ no longer fall back to a built-in DSN: they refuse
to start without one (scripts/maintenance_dsn.py::NoDatabaseConfigured), and
scripts/run_assessment_worker.py exits at import unless both its read DSN and
its write DSN are set. The guide used to say the opposite (it listed the
hard-coded fallback DSNs) and named no variable for the worker's writes, so an
operator following it would not know which variable a refusing job needs.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEPLOY_MD = REPO / "docs" / "deploy.md"
WORKER = REPO / "scripts" / "run_assessment_worker.py"
MAINTENANCE_DSN = REPO / "scripts" / "maintenance_dsn.py"


def section(title: str) -> str:
    text = DEPLOY_MD.read_text()
    m = re.search(rf"^### {re.escape(title)}\n.*?(?=^#{{2,3}} )", text, re.S | re.M)
    assert m, f"docs/deploy.md has no '### {title}' section"
    return m.group(0)


def test_the_python_scripts_section_describes_the_refusal_not_a_fallback():
    body = section("The Python scripts")
    # Calibration: the code still raises this, so the doc must name it.
    assert "class NoDatabaseConfigured" in MAINTENANCE_DSN.read_text()
    assert "NoDatabaseConfigured" in body, body[:400]
    assert "fall back to a hardcoded DSN" not in body
    assert "binds it to that script family's" not in body


def test_the_guide_lists_no_built_in_script_dsn():
    # The literal fallback DSNs the scripts used to carry; none is a default now.
    hits = re.findall(r"postgres(?:ql)?://epigraph(?:_admin|_ro)?:epigraph(?:_admin|_ro)?@", DEPLOY_MD.read_text())
    assert not hits, hits


def test_the_variable_tables_name_the_worker_write_dsn():
    worker = WORKER.read_text()
    # Calibration: the worker still writes on these two, in this order.
    assert 'os.environ.get("MAINTENANCE_DATABASE_URL")' in worker
    assert 'os.environ.get("DATABASE_ADMIN_URL")' in worker
    rows = [line for line in section("Other CLIs and scripts").splitlines() if line.startswith("| `")]
    admin = [r for r in rows if r.startswith("| `DATABASE_ADMIN_URL`")]
    assert admin and "run_assessment_worker.py" in admin[0], rows
    maint = next(r for r in rows if r.startswith("| `MAINTENANCE_DATABASE_URL`"))
    assert "run_assessment_worker.py" in maint, maint


def test_the_grow_row_does_not_promise_a_write_free_fresh_dry_run():
    step10 = section("Step 10 — Schedule the maintenance jobs")
    grow = next(line for line in step10.splitlines() if "theme_pipeline.py grow" in line and line.startswith("| "))
    assert "reports the plan without writing" not in grow, grow
    assert "--from-run-id" in grow and "discover" in grow, grow
