"""The deploy guide schedules the theme pipeline the code points operators at (backlog 469f3655).

`theme_cluster` is retired, and its refusal (THEME_CLUSTER_RETIRED in
crates/epigraph-mcp/src/tools/themes.rs) sends callers to two host jobs:
`scripts/maintain_themes.py` for incremental maintenance and
`theme_pipeline.py grow` for a periodic rebuild. `recall(diverse=true)` reads
the themes those jobs keep, yet docs/deploy.md's "Schedule the maintenance
jobs" step listed neither, so a deployment following the guide never ran them.

This ties the guide to the pointer in code: every script the refusal names
must have a row in Step 10's table, with the subcommand the refusal names.
It also checks that scripts/README.md says where the pinned Python
dependencies live (there is no scripts/requirements.txt).
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
THEMES_RS = REPO / "crates" / "epigraph-mcp" / "src" / "tools" / "themes.rs"
DEPLOY_MD = REPO / "docs" / "deploy.md"
SCRIPTS_README = REPO / "scripts" / "README.md"


def retired_message() -> str:
    src = THEMES_RS.read_text()
    m = re.search(r'pub const THEME_CLUSTER_RETIRED: &str = "(.*?)";', src, re.S)
    assert m, "THEME_CLUSTER_RETIRED not found in themes.rs"
    # A Rust string continuation (`\` + newline + indentation) is one space.
    return re.sub(r"\\\n\s*", "", m.group(1))


def step10() -> str:
    text = DEPLOY_MD.read_text()
    m = re.search(r"^### Step 10\b.*?(?=^### )", text, re.S | re.M)
    assert m, "docs/deploy.md has no '### Step 10' section"
    return m.group(0)


def table_rows(section: str) -> list[str]:
    return [line for line in section.splitlines() if line.startswith("| ") and "---" not in line]


def named_jobs(message: str) -> list[tuple[str, str | None]]:
    """(script, subcommand) pairs the refusal names: `scripts/x.py` or
    `x.py <subcommand>`."""
    jobs = []
    for m in re.finditer(r"(?:scripts/)?([a-z_]+\.py)(?: (grow|discover|project|label)\b)?", message):
        jobs.append((m.group(1), m.group(2)))
    return jobs


def test_the_refusal_still_names_the_theme_jobs():
    # Calibration: if the message stops naming scripts, the next test would
    # pass vacuously.
    jobs = named_jobs(retired_message())
    assert ("maintain_themes.py", None) in jobs, jobs
    assert ("theme_pipeline.py", "grow") in jobs, jobs


def test_step_10_schedules_every_theme_job_the_refusal_names():
    rows = table_rows(step10())
    assert rows, "Step 10 has no job table"
    missing = []
    for script, sub in named_jobs(retired_message()):
        needle = f"{script} {sub}" if sub else script
        if not any(needle in row for row in rows):
            missing.append(needle)
    assert not missing, (
        "THEME_CLUSTER_RETIRED points operators at these host jobs, but "
        f"docs/deploy.md Step 10 has no table row for them: {missing}"
    )


def test_the_theme_rows_state_role_cadence_and_memory():
    rows = [r for r in table_rows(step10()) if "theme_pipeline.py grow" in r or "maintain_themes.py" in r]
    grow = next(r for r in rows if "theme_pipeline.py grow" in r)
    maintain = next(r for r in rows if "maintain_themes.py" in r)
    # The rebuild connects on the maintenance DSN; maintenance runs over the API.
    assert "MAINTENANCE_DATABASE_URL" in grow
    assert "EPIGRAPH_TOKEN" in maintain
    # Each states a cadence and the rebuild states its memory.
    assert re.search(r"nightly|daily|weekly|monthly", maintain, re.I)
    assert re.search(r"nightly|daily|weekly|monthly", grow, re.I)
    assert re.search(r"\d(\.\d+)?\s*GB", grow), grow


def test_scripts_readme_names_the_pinned_dependency_file():
    readme = SCRIPTS_README.read_text()
    assert "tests/requirements-ci.txt" in readme
    assert (REPO / "tests" / "requirements-ci.txt").exists()


def test_the_rebuild_is_operator_run_with_the_flag_and_the_rebuild_steps():
    """A projection replaces every theme id, and the cascade drops the graph
    neighbourhoods and every Atlas layout and map with the old themes (backlog
    18ae37e7). Over existing themes the job refuses without
    --i-understand-full-rebuild, so a timer that runs it plain fails every run,
    and one that adds the flag wipes those views unattended with nothing to
    rebuild them. The row must say so, and send the operator to the rebuild."""
    flag = "--i-understand-full-rebuild"
    # Calibration: the flag the row names is the one the script takes.
    assert f'FULL_REBUILD_FLAG = "{flag}"' in (REPO / "scripts" / "project_to_themes.py").read_text()
    grow = next(r for r in table_rows(step10()) if "theme_pipeline.py grow" in r)
    cells = [c.strip() for c in grow.strip().strip("|").split("|")]
    command, cadence, notes = cells[1], cells[2], cells[3]
    assert flag in command, command
    assert re.search(r"on demand", cadence, re.I) and re.search(r"not a timer", cadence, re.I), cadence
    assert "rebuild_next" in notes, notes
    assert "docs/ops/theme-v2-promotion-runbook.md" in notes, notes
    assert "A projection is a full rebuild" in (
        REPO / "docs" / "ops" / "theme-v2-promotion-runbook.md").read_text()
    # The refusal sends callers to an operator job, not a periodic one.
    message = retired_message()
    assert "periodic" not in message, message
    assert flag in message, message
