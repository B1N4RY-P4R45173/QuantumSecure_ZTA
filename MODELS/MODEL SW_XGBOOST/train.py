"""
MODEL SW_XGBOOST — Sliding-window XGBoost.

Input = the current flow + statistics (mean, std, min, max, shares, unique ports)
of the last WINDOW flows in the time stream. This gives the tree model some
"memory" of recent traffic, without the cost of a neural network.

    python "MODEL SW_XGBOOST/train.py"
    python "MODEL SW_XGBOOST/train.py" --window 64
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common.gbm import run  # noqa: E402

if __name__ == "__main__":
    run(name="SW_XGBOOST", algo="xgboost", windowed=True, out_dir=HERE / "output")
