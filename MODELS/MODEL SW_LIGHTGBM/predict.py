"""
Run the saved sliding-window LightGBM model (output/model.txt).
The flows must be in time order; the first WINDOW-1 flows get no prediction.

    python "MODEL SW_LIGHTGBM/predict.py"                     # on the processed test stream
    python "MODEL SW_LIGHTGBM/predict.py" --csv new_flows.csv # on new CICFlowMeter flows
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common.gbm_predict import run_predict  # noqa: E402

if __name__ == "__main__":
    run_predict("SW_LIGHTGBM", HERE / "output")
