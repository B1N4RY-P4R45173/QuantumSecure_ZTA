"""The trained detector, run with numpy alone.

This replaces the synthetic RandomForest that stood in for the research
model. Both models here are the real ones from the final PC 2 evaluation run
(`runs/edge_inline_eval_20261104_164043`):

  * FLAT_cal  - LightGBM, 8 classes, re-fit on CICIoT2023 plus the site's own
                normal traffic. Answers "which attack category is this?"
  * AUTOENCODER - trained on local normal traffic only, flags a row whose
                reconstruction error exceeds the 99.5th percentile of
                held-out normal error. Answers "is this unlike anything
                normal?", which is how an attack absent from training
                (Ransomware, in that run) gets caught at all.

WHY THERE IS A TREE WALKER IN HERE instead of `import lightgbm`, and a matmul
chain instead of `import torch`: the Controller is a policy decision point.
Its job is to answer a knock in milliseconds and it already refuses to admit
anybody when it cannot. Adding torch to it means a ~2GB dependency, a CUDA
stack it will never use, and a much larger attack surface on the one service
whose compromise decides access - for six Linear layers that are 20KB of
weights. LightGBM is lighter but still a compiled extension on the critical
path. Neither earns its place when the forward pass is this small.

The risk of reimplementing is that it silently disagrees with the trained
model, so it is not trusted on the strength of the code reading correctly:
`tests/test_detector.py` replays 1,109 real rows sampled across all eight
categories and requires this module to reproduce the probabilities and the
anomaly flags that the real LightGBM and the real torch model produced for
those same rows on PC 2.

Nothing here is fitted, so there is no training path and no randomness. It
loads and evaluates.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

import numpy as np

_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = _ROOT / "MODELS" / "trained"

# The category order the multiclass model was trained with. Index 0 is the
# benign class, which is the only reason "probability of attack" can be read
# off a single softmax entry below.
NORMAL_CLASS = 0


# --------------------------------------------------------------------------- #
# LightGBM text model                                                         #
# --------------------------------------------------------------------------- #

@dataclass
class _Tree:
    split_feature: np.ndarray
    threshold: np.ndarray
    left_child: np.ndarray
    right_child: np.ndarray
    leaf_value: np.ndarray
    default_left: np.ndarray


class LightGBMText:
    """A reader and evaluator for LightGBM's own `model.txt` dump.

    Only the subset this model uses is supported, and anything else is
    refused rather than approximated - a detector that quietly mispredicts is
    worse than one that will not load. Specifically it requires
    `num_cat=0` (no categorical splits) and numerical `decision_type`s.
    """

    def __init__(self, path: str | Path) -> None:
        text = Path(path).read_text(encoding="utf-8")
        blocks = text.split("\n\n")

        header = blocks[0]
        self.num_class = int(_scalar(header, "num_class"))
        self.num_tree_per_iteration = int(_scalar(header, "num_tree_per_iteration"))
        self.max_feature_idx = int(_scalar(header, "max_feature_idx"))
        self.n_features = self.max_feature_idx + 1
        self.objective = _scalar(header, "objective")
        self.feature_names = _scalar(header, "feature_names").split()

        if "multiclass" not in self.objective:
            raise ValueError(
                f"only the multiclass objective is implemented, got {self.objective!r}")

        self.trees: list[_Tree] = []
        for block in blocks:
            if not block.lstrip().startswith("Tree="):
                continue
            if int(_scalar(block, "num_cat") or 0) != 0:
                raise ValueError("categorical splits are not implemented")

            decision = _ints(block, "decision_type")
            # LightGBM packs flags into decision_type: bit 0 marks a
            # categorical split, bit 1 marks "send missing values left".
            if (decision & 1).any():
                raise ValueError("categorical decision_type is not implemented")

            self.trees.append(_Tree(
                split_feature=_ints(block, "split_feature"),
                threshold=_floats(block, "threshold"),
                left_child=_ints(block, "left_child"),
                right_child=_ints(block, "right_child"),
                leaf_value=_floats(block, "leaf_value"),
                default_left=(decision & 2).astype(bool),
            ))

        if not self.trees:
            raise ValueError(f"no trees found in {path}")
        if len(self.trees) % self.num_tree_per_iteration:
            raise ValueError("tree count is not a whole number of iterations")

    # -- evaluation -------------------------------------------------------- #

    def raw_scores(self, X: np.ndarray) -> np.ndarray:
        """Summed leaf values per class, before the softmax.

        Trees are stored interleaved: iteration i contributes one tree per
        class, so tree k belongs to class k % num_tree_per_iteration.
        """
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if X.shape[1] != self.n_features:
            raise ValueError(
                f"model expects {self.n_features} features, got {X.shape[1]}")

        out = np.zeros((len(X), self.num_class), dtype=np.float64)
        for k, tree in enumerate(self.trees):
            out[:, k % self.num_tree_per_iteration] += _walk(tree, X)
        return out

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        raw = self.raw_scores(X)
        # Softmax, shifted by the row max so a large raw score cannot
        # overflow exp().
        raw -= raw.max(axis=1, keepdims=True)
        np.exp(raw, out=raw)
        raw /= raw.sum(axis=1, keepdims=True)
        return raw

    def attack_probability(self, X: np.ndarray) -> np.ndarray:
        """P(not benign), which is what the trust score cares about."""
        return 1.0 - self.predict_proba(X)[:, NORMAL_CLASS]


def _walk(tree: _Tree, X: np.ndarray) -> np.ndarray:
    """Vectorised traversal: every row descends this tree together.

    A child index is >= 0 for an internal node and negative for a leaf, where
    -k encodes leaf k-1. Rows that have landed on a leaf drop out of the
    active set, so the loop ends after at most the tree's depth.
    """
    node = np.zeros(len(X), dtype=np.int64)
    while True:
        internal = node >= 0
        if not internal.any():
            break
        idx = node[internal]
        feature = tree.split_feature[idx]
        value = X[internal, feature]
        threshold = tree.threshold[idx]

        go_left = value <= threshold
        # A missing value follows the split's recorded default rather than
        # comparing NaN, which would always be False and silently send every
        # such row right.
        missing = np.isnan(value)
        if missing.any():
            go_left = np.where(missing, tree.default_left[idx], go_left)

        node[internal] = np.where(go_left,
                                  tree.left_child[idx],
                                  tree.right_child[idx])
    return tree.leaf_value[-node - 1]


# -- model.txt field parsing ------------------------------------------------ #

def _scalar(block: str, key: str) -> str:
    for line in block.splitlines():
        if line.startswith(key + "="):
            return line[len(key) + 1:]
    return ""


def _ints(block: str, key: str) -> np.ndarray:
    raw = _scalar(block, key)
    return np.fromstring(raw, dtype=np.int64, sep=" ") if raw else np.zeros(0, np.int64)


def _floats(block: str, key: str) -> np.ndarray:
    raw = _scalar(block, key)
    return np.fromstring(raw, dtype=np.float64, sep=" ") if raw else np.zeros(0, np.float64)


# --------------------------------------------------------------------------- #
# Autoencoder                                                                 #
# --------------------------------------------------------------------------- #

class NumpyAutoencoder:
    """The trained autoencoder's forward pass, in numpy.

    The network is `Linear -> ReLU` repeated, with no activation on the final
    layer, so the whole thing is a chain of matmuls. The ordering comes from
    the saved state_dict keys (`0.weight`, `2.weight`, ... - the gaps are the
    ReLU modules, which hold no parameters).

    The input transform matters as much as the weights and is easy to get
    wrong: site_calibration.py applies `sign(x) * log1p(|x|)` to tame
    features whose range is enormous (Rate reaches 2.4e6), and only then
    standardises. Both steps are reproduced here, with mean and std taken
    from the trained model rather than recomputed from whatever rows happen
    to be on hand.
    """

    def __init__(self, npz_path: str | Path, meta_path: str | Path) -> None:
        data = np.load(npz_path)
        meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))

        self.features: list[str] = list(meta["features"])
        self.threshold = float(meta["threshold"])
        self.quantile = float(meta.get("quantile", 0.995))
        self.mean = np.asarray(data["__mean__"], dtype=np.float64)
        self.std = np.asarray(data["__std__"], dtype=np.float64)

        layers = sorted(
            {int(k.split(".")[0]) for k in data.files if not k.startswith("__")})
        self.layers = [(np.asarray(data[f"{i}.weight"], dtype=np.float64),
                        np.asarray(data[f"{i}.bias"], dtype=np.float64))
                       for i in layers]

    @staticmethod
    def _tame(X: np.ndarray) -> np.ndarray:
        return np.sign(X) * np.log1p(np.abs(X))

    def _prepare(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return (self._tame(X) - self.mean) / self.std

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Mean squared error per row. Higher means less like normal."""
        prepared = self._prepare(X)
        h = prepared
        for i, (weight, bias) in enumerate(self.layers):
            h = h @ weight.T + bias
            if i < len(self.layers) - 1:      # no ReLU on the output layer
                h = np.maximum(h, 0.0)
        return ((h - prepared) ** 2).mean(axis=1)

    def anomaly(self, X: np.ndarray) -> np.ndarray:
        return self.reconstruction_error(X) > self.threshold


# --------------------------------------------------------------------------- #
# The pair, loaded once                                                       #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Verdict:
    """What the detector says about one batch of flows for one device.

    Two different questions are kept apart here on purpose, because folding
    them together is a mistake I made first and the fixture caught:

      * `anomaly_rate` - the share of rows the classifier LABELS an attack
        (argmax away from Normal). This is the graded signal, and the plain
        meaning of the field's name.
      * `quarantine_hits` - rows meeting the much stricter rule the PC 2
        sweep actually validated: P(attack) >= 0.9 AND the autoencoder also
        calls the row unlike normal. This is the binary, act-on-it signal.

    Scoring the strict rule as if it were the rate understates real attacks
    badly. On the fixture's flood rows the classifier labels 149 of 150 an
    attack, but only 65 clear 0.9 - so a rate built from the strict gate
    reads 43% malicious for traffic that is almost entirely malicious, and
    would slip under a 50% tripwire.
    """
    flow_count: int
    malicious_flows: int         # rows labelled an attack
    anomaly_rate: float          # malicious_flows / flow_count
    top_class: str
    class_counts: dict[str, int]
    ae_flagged: int              # rows the autoencoder called unlike normal
    ae_rate: float
    quarantine_hits: int         # P >= 0.9 AND autoencoder agrees
    max_attack_probability: float


class Detector:
    """FLAT_cal plus the autoencoder, over rows of the 39 CICIoT2023 features."""

    #: a row is called an attack when P(not benign) reaches this. 0.9 is the
    #: quarantine threshold the PC 2 sweep settled on, not a guess.
    ATTACK_PROBABILITY = 0.9

    def __init__(self, model_dir: str | Path = MODEL_DIR) -> None:
        model_dir = Path(model_dir)
        self.gbm = LightGBMText(model_dir / "FLAT_cal" / "model.txt")
        meta = json.loads(
            (model_dir / "FLAT_cal" / "features.json").read_text(encoding="utf-8"))
        self.features: list[str] = list(meta["inputs"])
        self.categories: list[str] = list(meta["categories"])
        self.autoencoder = NumpyAutoencoder(
            model_dir / "AUTOENCODER" / "autoencoder_numpy.npz",
            model_dir / "AUTOENCODER" / "autoencoder.json")

        if self.autoencoder.features != self.features:
            raise ValueError(
                "the classifier and the autoencoder were trained on different "
                "feature orders; a row prepared for one would be scrambled "
                "for the other")

    def inspect(self, rows: list[dict] | np.ndarray) -> Verdict:
        """Score rows of features and summarise them for the trust scorer."""
        X = self._matrix(rows)
        if len(X) == 0:
            return Verdict(0, 0, 0.0, "benign", {}, 0, 0.0, 0, 0.0)

        proba = self.gbm.predict_proba(X)
        attack_p = 1.0 - proba[:, NORMAL_CLASS]
        labels = proba.argmax(axis=1)
        malicious = labels != NORMAL_CLASS

        counts: dict[str, int] = {}
        for label in labels:
            name = self.categories[int(label)]
            counts[name] = counts.get(name, 0) + 1

        # The reported top class is the most common ATTACK category, because
        # "mostly benign with a C2 beacon in it" is the interesting case and
        # a plain argmax over all rows would report Normal and bury it.
        attack_counts = {k: v for k, v in counts.items()
                         if k != self.categories[NORMAL_CLASS]}
        top = max(attack_counts, key=attack_counts.get) if attack_counts else "benign"

        ae_flags = self.autoencoder.anomaly(X)
        # The rule the PC 2 quarantine sweep validated: a confident classifier
        # call AND independent agreement from the anomaly detector. Requiring
        # both is what cut the share of normal traffic wrongly blocked from
        # 3.8% to well under 1% in that run.
        quarantine = (attack_p >= self.ATTACK_PROBABILITY) & ae_flags

        n = len(X)
        return Verdict(
            flow_count=n,
            malicious_flows=int(malicious.sum()),
            anomaly_rate=float(malicious.sum()) / n,
            top_class=top,
            class_counts=counts,
            ae_flagged=int(ae_flags.sum()),
            ae_rate=float(ae_flags.sum()) / n,
            quarantine_hits=int(quarantine.sum()),
            max_attack_probability=float(attack_p.max()),
        )

    def _matrix(self, rows: list[dict] | np.ndarray) -> np.ndarray:
        if isinstance(rows, np.ndarray):
            return rows if rows.ndim == 2 else rows.reshape(1, -1)
        if not rows:
            return np.zeros((0, len(self.features)))
        # Build by feature NAME, never by dict order: a telemetry writer that
        # emits the same 39 keys in a different order would otherwise score
        # against scrambled columns and look plausible while being wrong.
        return np.array([[_number(r.get(f)) for f in self.features] for r in rows],
                        dtype=np.float64)


def _number(value) -> float:
    if value is None or value == "":
        return math.nan
    try:
        return float(value)
    except (TypeError, ValueError):
        return math.nan


_DETECTOR: Detector | None = None


def load(model_dir: str | Path = MODEL_DIR) -> Detector:
    """The process-wide detector. Parsing 1,000 trees is not free, so it is
    done once; the object holds no per-request state."""
    global _DETECTOR
    if _DETECTOR is None:
        _DETECTOR = Detector(model_dir)
    return _DETECTOR
