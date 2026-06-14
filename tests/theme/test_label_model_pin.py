"""Unit test: the claude command line pins the haiku model."""
import inspect
from scripts import label_themes_llm as L


def test_claude_invocation_pins_haiku_model():
    src = inspect.getsource(L.call_claude_cli)
    assert "--model" in src
    assert "claude-haiku-4-5-20251001" in src
