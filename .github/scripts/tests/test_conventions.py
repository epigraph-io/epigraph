"""Run the convention suites (tests/conventions) in the `plan` job's blocking
step.

The `plan` job runs `python3 -m unittest discover -s .github/scripts/tests` on
every pull request, light-plan heads included, and a failure there stops the
run. The `python` job that runs the repository's other pytest suites is
advisory and off on light-plan heads, so a convention pin collected only there
would fail without blocking anything. This module puts the suites'
TestCase classes in its namespace, where unittest's loader collects them.

Standard library only, no database and no network.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.conventions.test_convention_pins import *  # noqa: E402,F401,F403
from tests.conventions.test_match_candidate_note import *  # noqa: E402,F401,F403
from tests.conventions.test_no_longer_in_force import *  # noqa: E402,F401,F403
