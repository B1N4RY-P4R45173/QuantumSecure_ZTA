"""
MODEL SW_LIGHTGBM — Sliding-window LightGBM.

Input = the current flow + statistics (mean, std, min, max, shares, unique ports)
of the last WINDOW flows in the time stream.

    python "MODEL SW_LIGHTGBM/train.py"
    python "MODEL SW_LIGHTGBM/train.py" --window 64
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common.gbm import run  # noqa: E402

if __name__ == "__main__":
    run(name="SW_LIGHTGBM", algo="lightgbm", windowed=True, out_dir=HERE / "output")
