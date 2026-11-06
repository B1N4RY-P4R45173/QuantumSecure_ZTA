"""
MODEL LSTM — Recurrent neural network over the last WINDOW flows.

Input  : a sequence of the last WINDOW flows (oldest -> newest), each flow = all features
Output : the class of the newest (current) flow

Unlike the sliding-window tree models, the LSTM sees the *order* of the flows,
not only summary statistics.

    python "MODEL LSTM/train.py"
    python "MODEL LSTM/train.py" --epochs 10 --hidden 128
    python "MODEL LSTM/train.py" --device cuda        # if you have an NVIDIA GPU
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
from torch import nn

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common import config as C                                   # noqa: E402
from common.bench import PeakMemory, latency_ms, timed            # noqa: E402
from common.data import load_meta, load_split                     # noqa: E402
from common.metrics import evaluate, save_result, text_report     # noqa: E402
from common.windows import Scaler, targets                        # noqa: E402

NAME = "LSTM"


class FlowLSTM(nn.Module):
    def __init__(self, n_features: int, n_classes: int, hidden: int, layers: int, dropout: float):
        super().__init__()
        self.lstm = nn.LSTM(n_features, hidden, num_layers=layers, batch_first=True,
                            dropout=dropout if layers > 1 else 0.0)
        self.head = nn.Sequential(nn.LayerNorm(hidden), nn.Linear(hidden, n_classes))

    def forward(self, x):                 # x: (batch, window, features)
        out, _ = self.lstm(x)
        return self.head(out[:, -1])      # use the state after the newest flow


def windows_at(Z: np.ndarray, pos: np.ndarray, window: int) -> np.ndarray:
    """Z[pos-window+1 .. pos] for every pos -> (len(pos), window, features)."""
    return Z[pos[:, None] + np.arange(-window + 1, 1)]


@torch.no_grad()
def predict(model, Z, pos, window, device, batch=4096) -> np.ndarray:
    model.eval()
    out = []
    for i in range(0, len(pos), batch):
        xb = torch.from_numpy(windows_at(Z, pos[i:i + batch], window)).to(device)
        out.append(model(xb).argmax(1).cpu().numpy())
    return np.concatenate(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="train LSTM")
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--samples-per-epoch", type=int, default=400_000,
                    help="random windows per epoch (keeps CPU training time reasonable)")
    ap.add_argument("--batch", type=int, default=512)
    ap.add_argument("--hidden", type=int, default=64)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--dropout", type=float, default=0.2)
    ap.add_argument("--lr", type=float, default=2e-3)
    ap.add_argument("--patience", type=int, default=2, help="stop after N epochs without val improvement")
    ap.add_argument("--window", type=int, default=None)
    ap.add_argument("--threads", type=int, default=0, help="CPU threads (0 = torch default)")
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto",
                    help="where to TRAIN (auto = CUDA GPU if available)")
    ap.add_argument("--bench-device", choices=["cpu", "cuda"], default="cpu",
                    help="where to TEST and measure speed (default cpu: edge gateways have no GPU)")
    args = ap.parse_args()

    torch.manual_seed(C.SEED)
    rng = np.random.default_rng(C.SEED)
    if args.threads > 0:
        torch.set_num_threads(args.threads)
    if args.device == "cuda" and not torch.cuda.is_available():
        print("WARNING: CUDA requested but not available (CPU-only torch, or no driver) -> using CPU")
    use_cuda = args.device in ("auto", "cuda") and torch.cuda.is_available()
    device = torch.device("cuda" if use_cuda else "cpu")
    if use_cuda:
        torch.backends.cudnn.benchmark = True
        print(f"[{NAME}] GPU: {torch.cuda.get_device_name(0)}")
    bench_device = torch.device(args.bench_device if torch.cuda.is_available() else "cpu")

    meta = load_meta()
    if meta["quick"]:
        print(f"[{NAME}] WARNING: processed data is from --quick mode. Run preprocess.py for real results.")
    window = args.window or meta["window"]
    feats = meta["features"]
    perf: dict = {}

    with PeakMemory() as mem:
        print(f"[{NAME}] loading and scaling (window={window}, device={device}) ...")
        dfs = {s: load_split(s) for s in ("train", "val", "test")}
        scaler = Scaler().fit(dfs["train"][feats].to_numpy(np.float32))
        Z, Y, B, P = {}, {}, {}, {}
        for s, df in dfs.items():
            with timed(perf, f"features_{s}_s"):
                Z[s] = scaler.transform(df[feats].to_numpy(np.float32))
            y, b = targets(df, window)
            Y[s], B[s] = y, b
            P[s] = np.arange(window - 1, len(df))          # positions that have a full window
            print(f"   {s:5s} {len(P[s]):,} windows")
        del dfs

        n_classes = len(C.CLASSES)
        counts = np.bincount(Y["train"], minlength=n_classes).astype(np.float64)
        w = np.where(counts > 0, (counts.sum() / (np.count_nonzero(counts) * np.maximum(counts, 1))) ** 0.5, 0.0)
        loss_fn = nn.CrossEntropyLoss(weight=torch.tensor(w, dtype=torch.float32, device=device))

        model = FlowLSTM(len(feats), n_classes, args.hidden, args.layers, args.dropout).to(device)
        opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
        sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=args.epochs)

        val_pos = P["val"] if len(P["val"]) <= 200_000 else np.sort(rng.choice(P["val"], 200_000, replace=False))
        val_y = Y["val"][val_pos - (window - 1)]
        best_f1, best_state, bad = -1.0, None, 0

        print(f"[{NAME}] training ...")
        t_train = time.perf_counter()
        for epoch in range(1, args.epochs + 1):
            model.train()
            k = min(args.samples_per_epoch, len(P["train"]))
            idx = rng.choice(len(P["train"]), k, replace=False)
            total, t0 = 0.0, time.perf_counter()
            for i in range(0, k, args.batch):
                bi = idx[i:i + args.batch]
                xb = torch.from_numpy(windows_at(Z["train"], P["train"][bi], window)).to(device)
                yb = torch.from_numpy(Y["train"][bi]).to(device)
                opt.zero_grad()
                loss = loss_fn(model(xb), yb)
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
                total += loss.item() * len(bi)
            sched.step()

            vp = predict(model, Z["val"], val_pos, window, device)
            vf1 = evaluate(val_y, vp)["macro_f1"]
            print(f"   epoch {epoch}: loss {total / k:.4f}  val macro-F1 {vf1:.4f}  [{time.perf_counter() - t0:.0f}s]")
            if vf1 > best_f1:
                best_f1, bad = vf1, 0
                best_state = {k_: v.detach().clone() for k_, v in model.state_dict().items()}
            else:
                bad += 1
                if bad >= args.patience:
                    print("   early stopping")
                    break
        perf["train_time_s"] = time.perf_counter() - t_train
        model.load_state_dict(best_state)

        model = model.to(bench_device)
        print(f"[{NAME}] testing on {bench_device} ...")
        with timed(perf, "predict_test_s"):
            y_pred = predict(model, Z["test"], P["test"], window, bench_device)

    # ---- speed
    n = len(P["test"])
    total_s = perf["features_test_s"] + perf["predict_test_s"]
    model.eval()
    samples = [torch.from_numpy(windows_at(Z["test"], P["test"][i:i + 1], window)).to(bench_device)
               for i in range(0, min(n, 3000), 10)]
    with torch.no_grad():
        lat = latency_ms(model, samples) + perf["features_test_s"] / n * 1000

    # ---- save
    out_dir = HERE / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "model.pt"
    torch.save({"state_dict": {k: v.cpu() for k, v in model.state_dict().items()}, "scaler": scaler.state(), "features": feats,
                "window": window, "classes": C.CLASSES, "args": vars(args)}, model_path)

    res = evaluate(Y["test"], y_pred, B["test"])
    report = text_report(NAME, Y["test"], y_pred, res)
    (out_dir / "report.txt").write_text(report, encoding="utf-8")
    print("\n" + report)

    save_result(NAME, {
        "family": "LSTM (recurrent neural network)",
        "input": f"sequence of the last {window} flows",
        "window_flows": window,
        "needs_flow_end": True,
        "can_drop_first_packet": False,
        "quick_data": meta["quick"],
        "detection": res,
        "performance": {
            "train_time_s": perf["train_time_s"],
            "model_size_mb": model_path.stat().st_size / 2**20,
            "test_flows": n,
            "throughput_flows_per_s": n / total_s,
            "equiv_packets_per_s": n / total_s * meta["avg_packets_per_flow_test"],
            "latency_ms_single": lat,
            "peak_ram_mb": mem.peak_mb,
            "n_features": len(feats),
            "train_device": str(device),
            "speed_measured_on": str(bench_device),
            "best_val_macro_f1": best_f1,
        },
        "notes": [
            "Throughput excludes CICFlowMeter feature extraction from packets (it is optimistic for ML).",
            f"Trained on {device}, speed measured on {bench_device} (edge gateways rarely have a GPU).",
        ],
    })
    (out_dir / "train_args.json").write_text(json.dumps(vars(args), indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
