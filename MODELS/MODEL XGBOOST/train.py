"""
MODEL XGBOOST — XGBoost on single flows (no time window).

Baseline: shows how well a tree model does when it sees only one flow at a time.

    python "MODEL XGBOOST/train.py"
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common.gbm import run  # noqa: E402

if __name__ == "__main__":
    run(name="XGBOOST", algo="xgboost", windowed=False, out_dir=HERE / "output")
