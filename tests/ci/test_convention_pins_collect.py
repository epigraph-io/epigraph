"""Run the convention pins (tests/conventions) in the required Python job.

That job runs `python3 -m pytest -rs tests/ci tests/scifact_calibration`, so a
suite outside those directories is collected only through a module here. The
star import puts the pin suite's TestCase classes in this module's namespace,
where pytest collects them. Remove this file once the job's pytest line names
tests/conventions itself.
"""

from tests.conventions.test_convention_pins import *  # noqa: F401,F403
