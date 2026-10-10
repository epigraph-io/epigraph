"""Unit tests: which theme labels label_themes_llm treats as placeholders."""
import pytest

from scripts import label_themes_llm as L


@pytest.mark.parametrize("label", [
    None,
    "",
    "auto-07",
    "cluster-135",
    "cluster-split-1a2b3c4d-1",
    "x" * 60,
    "Graph coherence is defined as the share of edges that agree",
    "Coherence defined as: agreement",
])
def test_placeholders_are_relabelled(label):
    assert L.is_placeholder_label(label)


@pytest.mark.parametrize("label", [
    "Renal Filtration And Urine Formation",
    "DNA Structure and Molecular Recognition",
    "Nanoscale Surface Science And Engineering",
])
def test_llm_written_names_are_kept(label):
    assert not L.is_placeholder_label(label)
