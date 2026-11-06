"""
Run the saved LightGBM model (output/model.txt).

    python "MODEL LIGHTGBM/predict.py"                     # on the processed test stream
    python "MODEL LIGHTGBM/predict.py" --csv new_flows.csv # on new CICFlowMeter flows
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common.gbm_predict import run_predict  # noqa: E402

if __name__ == "__main__":
    run_predict("LIGHTGBM", HERE / "output")
