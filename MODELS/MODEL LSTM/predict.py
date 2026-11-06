"""
Run the saved LSTM model (output/model.pt).
The flows must be in time order; the first WINDOW-1 flows get no prediction.

    python "MODEL LSTM/predict.py"                     # on the processed test stream
    python "MODEL LSTM/predict.py" --csv new_flows.csv # on new CICFlowMeter flows
"""

import sys
import time
from pathlib import Path

import numpy as np
import torch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from common.infer import load_input, parse_args, write_output  # noqa: E402
from common.windows import Scaler                                # noqa: E402
from train import FlowLSTM, windows_at                           # noqa: E402


def main() -> None:
    args = parse_args("LSTM")
    path = HERE / "output" / "model.pt"
    if not path.exists():
        raise SystemExit(f"no saved model at {path} — run train.py first")
    ckpt = torch.load(path, map_location="cpu")
    a = ckpt["args"]
    feats, window, classes = ckpt["features"], ckpt["window"], ckpt["classes"]

    model = FlowLSTM(len(feats), len(classes), a["hidden"], a["layers"], a["dropout"])
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    scaler = Scaler()
    scaler.mean = np.array(ckpt["scaler"]["mean"], np.float32)
    scaler.std = np.array(ckpt["scaler"]["std"], np.float32)

    df, meta, y_true, source = load_input(args, feats)
    if len(df) < window:
        raise SystemExit(f"need at least {window} flows for the LSTM")
    Z = scaler.transform(df[feats].to_numpy(np.float32))
    pos = np.arange(window - 1, len(df))

    t0 = time.perf_counter()
    probs = []
    with torch.no_grad():
        for i in range(0, len(pos), 4096):
            xb = torch.from_numpy(windows_at(Z, pos[i:i + 4096], window))
            probs.append(torch.softmax(model(xb), dim=1).numpy())
    prob = np.concatenate(probs)
    print(f"[LSTM] predicted {len(pos):,} flows in {time.perf_counter() - t0:.2f}s")

    write_output(HERE / "output", args, source, meta, window - 1, classes, prob, y_true, "LSTM")


if __name__ == "__main__":
    main()
