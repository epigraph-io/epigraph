"""Tests for test_conformal_coverage.check_shipped, the `--check` mode (backlog 733df577).

In CI `--check` only ever reads the faithful calibration.toml, so its drift
branches would never fire there. These tests write altered copies of the
shipped file and assert each alteration is refused, and that the unaltered copy
passes, so an edit that made check_shipped vacuous fails CI.
"""
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_conformal_coverage as tcc  # noqa: E402
from calibrate_conformal import (  # noqa: E402  (scripts/ is on sys.path via tcc)
    ALPHA, CALIBRATION_TOML, CONFORMAL_MARKER, SEED, conformal_comment, fit_quantiles,
    load_fixtures,
)

SHIPPED = CALIBRATION_TOML.read_text()


@pytest.fixture(scope="module")
def fx():
    return load_fixtures()


def write(tmp_path, text):
    path = tmp_path / "calibration.toml"
    path.write_text(text)
    return path


def replace_once(text, old, new):
    assert text.count(old) == 1, f"expected exactly one {old!r} in calibration.toml"
    return text.replace(old, new)


def quantile_line(cls):
    m = re.search(rf"^{cls}\s*=\s*([0-9.]+)\s*$", SHIPPED.split("[conformal.quantiles]", 1)[1], re.M)
    assert m, f"no {cls} line under [conformal.quantiles]"
    return m.group(0), float(m.group(1))


def shipped_comment():
    start = SHIPPED.index(CONFORMAL_MARKER)
    return SHIPPED[start:SHIPPED.index("\n[conformal]\n", start) + 1]


def old_split_wording(n_by, n_total):
    """The comment the calibrator wrote before 733df577: it reads as a held-out
    split of the n fixtures, but the shipped quantiles were fit on all of them."""
    return (
        f"{CONFORMAL_MARKER} ────────────────\n"
        f"# Per-class nonconformity quantiles q_c, fit by scripts/calibrate_conformal.py\n"
        f"# over {n_total} labelled SciFact fixtures (split-conformal, alpha={ALPHA},\n"
        f"# seed={SEED}). score_c = 1 - BetP_c (supported/contradicted) or 1 - theta (NEI);\n"
        f"# class c is in the prediction set iff score_c <= q_c. Calibration n per class:\n"
        f"# supported={n_by['supported']} contradicted={n_by['contradicted']} "
        f"not_enough_info={n_by['not_enough_info']}.\n"
    )


def test_the_unaltered_shipped_file_passes(fx, tmp_path):
    q = tcc.check_shipped(fx, write(tmp_path, SHIPPED))
    assert set(q) == {"supported", "contradicted", "not_enough_info"}


@pytest.mark.parametrize("cls", ["supported", "contradicted", "not_enough_info"])
def test_a_quantile_shifted_by_1e_5_is_drift(fx, tmp_path, cls):
    line, value = quantile_line(cls)
    drifted = line.replace(f"{value:.6f}", f"{value + 1e-5:.6f}")
    assert drifted != line
    with pytest.raises(AssertionError, match="disagree with a refit"):
        tcc.check_shipped(fx, write(tmp_path, replace_once(SHIPPED, line, drifted)))


def test_a_changed_alpha_is_refused(fx, tmp_path):
    text = replace_once(SHIPPED, f"[conformal]\nalpha = {ALPHA}\n", "[conformal]\nalpha = 0.05\n")
    with pytest.raises(AssertionError, match="shipped alpha"):
        tcc.check_shipped(fx, write(tmp_path, text))


def test_a_missing_class_is_refused(fx, tmp_path):
    line, _ = quantile_line("not_enough_info")
    with pytest.raises(AssertionError, match="not_enough_info"):
        tcc.check_shipped(fx, write(tmp_path, replace_once(SHIPPED, line + "\n", "")))


def test_no_conformal_section_is_refused(fx, tmp_path):
    start = SHIPPED.index(CONFORMAL_MARKER)
    end = SHIPPED.index("\n#", SHIPPED.index("[conformal.quantiles]"))
    with pytest.raises(AssertionError, match="no \\[conformal\\] section"):
        tcc.check_shipped(fx, write(tmp_path, SHIPPED[:start] + SHIPPED[end + 1:]))


def test_a_missing_marker_comment_is_refused(fx, tmp_path):
    text = replace_once(SHIPPED, shipped_comment(), "")
    with pytest.raises(AssertionError, match="comment above"):
        tcc.check_shipped(fx, write(tmp_path, text))


def test_the_old_split_wording_is_refused(fx, tmp_path):
    _, n_by = fit_quantiles(fx, ALPHA)
    text = replace_once(SHIPPED, shipped_comment(), old_split_wording(n_by, len(fx)))
    with pytest.raises(AssertionError):
        tcc.check_shipped(fx, write(tmp_path, text))


def test_a_wrong_calibration_n_is_refused(fx, tmp_path):
    text = replace_once(SHIPPED, f"on ALL {len(fx)} labelled", f"on ALL {len(fx) - 1} labelled")
    with pytest.raises(AssertionError):
        tcc.check_shipped(fx, write(tmp_path, text))


def test_the_old_wording_is_refused_even_when_the_generator_writes_it(fx, tmp_path, monkeypatch):
    # The comment check compares the shipped text with the generator's. If a
    # later edit restored the misleading held-out-split wording in BOTH places,
    # that comparison alone would pass; the check must still reject the claim.
    _, n_by = fit_quantiles(fx, ALPHA)
    old = old_split_wording(n_by, len(fx))
    monkeypatch.setattr(tcc, "conformal_comment", lambda n_by, n_total: old_split_wording(n_by, n_total))
    text = replace_once(SHIPPED, shipped_comment(), old)
    with pytest.raises(AssertionError, match="full corpus|ALL"):
        tcc.check_shipped(fx, write(tmp_path, text))


def test_a_wrong_per_class_n_is_refused(fx, tmp_path):
    # Only the comparison with the generator catches this: the total and the
    # full-corpus wording are still right.
    _, n_by = fit_quantiles(fx, ALPHA)
    old = f"supported={n_by['supported']} "
    text = replace_once(SHIPPED, old, f"supported={n_by['supported'] - 1} ")
    with pytest.raises(AssertionError, match="does not state the fit's population"):
        tcc.check_shipped(fx, write(tmp_path, text))


def test_a_held_out_claim_in_other_words_is_refused_even_from_the_generator(fx, tmp_path, monkeypatch):
    # Not the old phrase, but the same false claim (a held-out calibration
    # split), written by the generator and the toml alike: the positive
    # "on ALL <n>" / "the full corpus" pin is what rejects it.
    def held_out_wording(n_by, n_total):
        return replace_once(
            conformal_comment(n_by, n_total),
            f"on ALL {n_total} labelled SciFact fixtures (alpha={ALPHA}). No held-out split:\n"
            f"# the calibration n is the full corpus.",
            f"on a 50% calibration split of {n_total} labelled SciFact fixtures (alpha={ALPHA}).\n"
            f"# The other half is held out.",
        )
    _, n_by = fit_quantiles(fx, ALPHA)
    text = replace_once(SHIPPED, shipped_comment(), held_out_wording(n_by, len(fx)))
    monkeypatch.setattr(tcc, "conformal_comment", held_out_wording)
    with pytest.raises(AssertionError, match="full corpus"):
        tcc.check_shipped(fx, write(tmp_path, text))


def test_a_comment_that_also_claims_a_split_is_refused_even_from_the_generator(fx, tmp_path, monkeypatch):
    # The full-corpus statement is present, but so is the old held-out-split
    # phrase: the comment contradicts itself, and the negative pin rejects it.
    def contradictory(n_by, n_total):
        return conformal_comment(n_by, n_total) + f"# (split-conformal, alpha={ALPHA}, seed={SEED})\n"
    _, n_by = fit_quantiles(fx, ALPHA)
    text = replace_once(SHIPPED, shipped_comment(), contradictory(n_by, len(fx)))
    monkeypatch.setattr(tcc, "conformal_comment", contradictory)
    with pytest.raises(AssertionError, match="held-out split"):
        tcc.check_shipped(fx, write(tmp_path, text))
