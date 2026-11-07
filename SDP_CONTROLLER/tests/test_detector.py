"""The numpy detector must agree with the trained models, not merely run.

detector.py reimplements LightGBM's tree walk and the autoencoder's forward
pass so the Controller needs neither lightgbm nor torch. That trade is only
worth making if the reimplementation is exact, and "the code looks right" is
not evidence: a wrong missing-value default, a transposed weight or a
forgotten log1p all produce plausible numbers.

So these tests replay `detector_fixture.csv` - 1,109 real rows sampled across
all eight categories from the final PC 2 run
(runs/edge_inline_eval_20261104_164043, 1,754,833 rows) - and require this
module to reproduce, for those same rows:

  * `p_attack_FLAT_cal`, the attack probability the real LightGBM produced;
  * `ae_flag`, the anomaly decision the real torch autoencoder produced.

If a test here fails, trust the fixture and fix detector.py.
"""

from __future__ import annotations

import csv
import math
import sys
from pathlib import Path

import numpy as np
import pytest

_HERE = Path(__file__).resolve().parent
_CONTROLLER = _HERE.parent
_ROOT = _CONTROLLER.parent
for _p in (str(_ROOT), str(_CONTROLLER)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

FIXTURE = _HERE / "detector_fixture.csv"
MODELS = _ROOT / "MODELS" / "trained"

pytestmark = pytest.mark.skipif(
    not (FIXTURE.exists() and (MODELS / "FLAT_cal" / "model.txt").exists()),
    reason="needs MODELS/trained/ and the recorded fixture from the PC 2 run",
)


@pytest.fixture(scope="module")
def detector():
    from detection.detector import Detector
    return Detector(MODELS)


@pytest.fixture(scope="module")
def fixture_rows(detector):
    """Real feature rows with the predictions the trained models made."""
    with FIXTURE.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows, "fixture is empty"

    X = np.array([[float(r[f]) for f in detector.features] for r in rows],
                 dtype=np.float64)
    expected_p = np.array([float(r["p_attack_FLAT_cal"]) for r in rows])
    expected_ae = np.array([_as_bool(r["ae_flag"]) for r in rows])
    categories = [r["category"] for r in rows]
    return X, expected_p, expected_ae, categories, rows


def _as_bool(text: str) -> bool:
    return str(text).strip().lower() in {"true", "1", "1.0", "yes"}


# --------------------------------------------------------------------------- #
# The classifier                                                              #
# --------------------------------------------------------------------------- #

def test_the_model_loads_with_the_shape_it_was_trained_with(detector):
    assert detector.gbm.num_class == 8
    assert detector.gbm.num_tree_per_iteration == 8
    assert detector.gbm.n_features == 39
    assert len(detector.features) == 39
    # Interleaved one tree per class per iteration.
    assert len(detector.gbm.trees) % 8 == 0
    assert detector.categories[0] == "Normal", (
        "attack probability is read as 1 - P(class 0), so the benign class "
        "must be first")


def test_attack_probability_matches_the_trained_lightgbm(fixture_rows, detector):
    """The headline check: same rows, same probabilities."""
    X, expected, _, _, _ = fixture_rows
    got = detector.gbm.attack_probability(X)

    assert got.shape == expected.shape
    worst = float(np.max(np.abs(got - expected)))
    assert worst < 1e-6, (
        f"largest disagreement with the trained model is {worst:.3g} over "
        f"{len(X)} rows; the tree walk or the softmax is wrong")


def test_probabilities_are_a_distribution(fixture_rows, detector):
    X, _, _, _, _ = fixture_rows
    proba = detector.gbm.predict_proba(X)
    assert proba.shape == (len(X), 8)
    assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-9)
    assert (proba >= 0).all()


def test_benign_and_attack_rows_are_actually_separated(fixture_rows, detector):
    """Guards against an "exact" match to a model that predicts one value.

    A bug that made every probability identical would satisfy the comparison
    above only if the fixture were also constant, but this pins the
    separation directly: normal rows must score low and flood rows high.
    """
    X, _, _, categories, _ = fixture_rows
    p = detector.gbm.attack_probability(X)
    cats = np.array(categories)

    normal = p[cats == "Normal"]
    flood = p[cats == "Flood DoS/DDoS"]
    assert normal.mean() < 0.5, f"normal rows average {normal.mean():.3f}"
    assert flood.mean() > 0.5, f"flood rows average {flood.mean():.3f}"


# --------------------------------------------------------------------------- #
# The autoencoder                                                             #
# --------------------------------------------------------------------------- #

def test_autoencoder_flags_match_the_trained_torch_model(fixture_rows, detector):
    X, _, expected, _, _ = fixture_rows
    got = detector.autoencoder.anomaly(X)

    disagreements = int((got != expected).sum())
    assert disagreements == 0, (
        f"{disagreements}/{len(X)} rows disagree with the torch autoencoder; "
        f"check the log1p transform, the mean/std, or the layer order")


def test_autoencoder_threshold_is_the_trained_one(detector):
    assert detector.autoencoder.threshold == pytest.approx(0.2771055996417999)
    assert detector.autoencoder.quantile == pytest.approx(0.995)
    # 39 -> 32 -> 16 -> 8 -> 16 -> 32 -> 39 is six weight matrices.
    assert len(detector.autoencoder.layers) == 6


def test_reconstruction_error_is_finite_and_positive(fixture_rows, detector):
    X, _, _, _, _ = fixture_rows
    err = detector.autoencoder.reconstruction_error(X)
    assert np.isfinite(err).all()
    assert (err >= 0).all()


# --------------------------------------------------------------------------- #
# The summary the trust scorer consumes                                       #
# --------------------------------------------------------------------------- #

def test_inspect_summarises_a_benign_device(fixture_rows, detector):
    X, _, _, categories, _ = fixture_rows
    normal = X[np.array(categories) == "Normal"]
    verdict = detector.inspect(normal)

    assert verdict.flow_count == len(normal)
    assert verdict.anomaly_rate < 0.5, (
        f"normal traffic came out {verdict.anomaly_rate:.0%} malicious")


def test_inspect_summarises_an_attacking_device(fixture_rows, detector):
    X, _, _, categories, _ = fixture_rows
    flood = X[np.array(categories) == "Flood DoS/DDoS"]
    verdict = detector.inspect(flood)

    assert verdict.anomaly_rate > 0.5, (
        f"flood traffic came out only {verdict.anomaly_rate:.0%} malicious")
    assert verdict.top_class != "benign"
    assert verdict.max_attack_probability > 0.9
    assert verdict.quarantine_hits > 0, "no quarantine-grade evidence at all"


def test_the_rate_and_the_quarantine_rule_are_not_the_same_number(fixture_rows,
                                                                  detector):
    """Pins the distinction the fixture forced.

    The strict rule (P >= 0.9 and the autoencoder agreeing) is deliberately
    far narrower than "the classifier labelled this an attack". Collapsing
    the two made flood traffic read 43% malicious instead of 99%, which would
    duck a 50% tripwire. If these ever coincide, one of them has lost its
    meaning.
    """
    X, _, _, categories, _ = fixture_rows
    flood = X[np.array(categories) == "Flood DoS/DDoS"]
    verdict = detector.inspect(flood)

    assert verdict.quarantine_hits < verdict.malicious_flows, (
        "the strict quarantine rule is no stricter than the plain label")
    assert verdict.anomaly_rate > 0.9


def test_the_unseen_attack_is_caught_by_the_autoencoder(fixture_rows, detector):
    """The reason the autoencoder is in the architecture at all.

    Ransomware was not in the training categories, so the classifier has no
    label for it. The anomaly detector is what notices it anyway.
    """
    X, _, _, categories, _ = fixture_rows
    unseen = X[np.array([c.startswith("Ransomware") for c in categories])]
    assert len(unseen), "fixture lost the unseen-attack rows"

    verdict = detector.inspect(unseen)
    assert verdict.ae_rate > 0.5, (
        f"the autoencoder flagged only {verdict.ae_rate:.0%} of an attack it "
        f"was never trained on; that is the zero-day claim failing")


def test_rows_are_read_by_feature_name_not_dict_order(detector):
    """A telemetry writer emitting the same keys in another order must score
    the same. Positional reading would scramble the columns silently."""
    row = {f: float(i) for i, f in enumerate(detector.features)}
    shuffled = dict(reversed(list(row.items())))

    a = detector.gbm.attack_probability(detector._matrix([row]))
    b = detector.gbm.attack_probability(detector._matrix([shuffled]))
    assert a[0] == pytest.approx(b[0])


def test_a_missing_feature_does_not_crash_or_silently_read_zero(detector):
    """An absent value becomes NaN and follows the split's recorded default,
    which is what LightGBM itself does. Reading it as 0.0 would be a
    different, confidently wrong answer."""
    row = {f: 1.0 for f in detector.features}
    del row[detector.features[3]]            # Rate

    X = detector._matrix([row])
    assert math.isnan(X[0, 3])
    p = detector.gbm.attack_probability(X)
    assert np.isfinite(p).all()


def test_an_empty_batch_is_not_an_accusation(detector):
    verdict = detector.inspect([])
    assert verdict.flow_count == 0
    assert verdict.anomaly_rate == 0.0
    assert verdict.top_class == "benign"
