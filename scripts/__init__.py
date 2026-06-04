"""Make scripts/ importable as a package.

Adds the scripts directory to sys.path so that bare `import theme_lib`
statements inside the scripts (which work when run directly) also resolve
when the scripts are imported as `from scripts import <module>` by tests.
"""
import os
import sys

_scripts_dir = os.path.dirname(os.path.abspath(__file__))
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)
