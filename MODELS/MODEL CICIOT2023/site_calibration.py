"""
Site calibration: the gateway learns ITS OWN normal traffic after install (no attack labels needed).

Two parts, both use only local NORMAL rows recorded during a learning period:
  1. Re-fit the attack model (BAL_MS / FLAT, LightGBM) on: the original CICIoT2023 training data
     (= attack knowledge, unchanged) + the local normal rows (labelled "Normal").
     The CICIoT2023 data is rebuilt with the exact settings of the base run (its config.json).
  2. Autoencoder baseline (PyTorch) trained on the local normal rows only. Reconstruction error above
     a threshold (AE_QUANTILE of the error on held-out local normal rows) = "anomaly" (unknown attack).

Used by edge_inline_eval.py --calibrate-share (library). Not run on its own.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import train_ciciot2023 as tc                                           # noqa: E402

# ---------------------------------------------------------------- settings
LOCAL_WEIGHT = 2.0          # extra weight for local normal rows (they are the site's real "normal")
MIX_ATTACK_SHARE = 0.30     # CICIoT2023 attack rows inserted into every local normal stream (bursts + solo),
                            # so window models learn "attack INSIDE this site's normal" (no site attack labels)
AE_HIDDEN = (32, 16, 8)     # encoder sizes; decoder mirrors it
AE_EPOCHS = 30
AE_BATCH = 2048
AE_LR = 1e-3
AE_QUANTILE = 0.995         # threshold = 99.5% of the error on held-out local normal rows
SEED = 42


# ---------------------------------------------------------------- autoencoder
class AutoencoderBaseline:
    def __init__(self, features: list[str]):
        self.features = features
        self.mean = self.std = None
        self.net = None
        self.threshold = None
        self.device = "cpu"

    @staticmethod
    def _transform(X: np.ndarray) -> np.ndarray:
        return np.sign(X) * np.log1p(np.abs(X))                      # tame big values (Rate, Variance, ...)

    def _prep(self, df: pd.DataFrame) -> np.ndarray:
        X = self._transform(df[self.features].to_numpy(np.float64))
        return ((X - self.mean) / self.std).astype(np.float32)

    def fit(self, train: pd.DataFrame, val: pd.DataFrame, log) -> dict:
        import torch
        from torch import nn
        torch.manual_seed(SEED)
        np.random.seed(SEED)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        Xt = self._transform(train[self.features].to_numpy(np.float64))
        self.mean, self.std = Xt.mean(0), Xt.std(0) + 1e-6
        Xt = ((Xt - self.mean) / self.std).astype(np.float32)
        Xv = self._prep(val)
        d = Xt.shape[1]
        layers, prev = [], d
        for h in AE_HIDDEN:
            layers += [nn.Linear(prev, h), nn.ReLU()]
            prev = h
        for h in list(AE_HIDDEN[-2::-1]) + [d]:
            layers += [nn.Linear(prev, h)] + ([nn.ReLU()] if h != d else [])
            prev = h
        self.net = nn.Sequential(*layers).to(self.device)
        opt = torch.optim.Adam(self.net.parameters(), lr=AE_LR)
        loss_fn = nn.MSELoss()
        xt = torch.from_numpy(Xt).to(self.device)
        t0 = time.time()
        for ep in range(AE_EPOCHS):
            perm = torch.randperm(len(xt), device=self.device)
            tot = 0.0
            for i in range(0, len(xt), AE_BATCH):
                b = xt[perm[i:i + AE_BATCH]]
                opt.zero_grad()
                loss = loss_fn(self.net(b), b)
                loss.backward()
                opt.step()
                tot += float(loss.detach()) * len(b)
            if ep % 10 == 0 or ep == AE_EPOCHS - 1:
                log.info("   autoencoder epoch %2d  train MSE %.5f", ep, tot / len(xt))
        err_v = self._errors(Xv)
        self.threshold = float(np.quantile(err_v, AE_QUANTILE))
        info = {"device": self.device, "train_rows": len(Xt), "val_rows": len(Xv), "epochs": AE_EPOCHS,
                "threshold": self.threshold, "val_error_median": float(np.median(err_v)),
                "seconds": round(time.time() - t0, 1)}
        log.info("   autoencoder threshold %.4f (%.1f%% of held-out local normal rows) on %s, %.0f s",
                 self.threshold, 100 * AE_QUANTILE, self.device, info["seconds"])
        return info

    def _errors(self, X: np.ndarray) -> np.ndarray:
        import torch
        self.net.eval()
        out = []
        with torch.no_grad():
            for i in range(0, len(X), 65536):
                b = torch.from_numpy(X[i:i + 65536]).to(self.device)
                out.append(((self.net(b) - b) ** 2).mean(1).cpu().numpy())
        return np.concatenate(out) if out else np.zeros(0)

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """Reconstruction error per row (higher = more unusual)."""
        if len(df) == 0:
            return np.zeros(0)
        return self._errors(self._prep(df))

    def save(self, folder: Path) -> None:
        import torch
        folder.mkdir(parents=True, exist_ok=True)
        torch.save(self.net.state_dict(), folder / "autoencoder.pt")
        tc.write_json(folder / "autoencoder.json", {"features": self.features, "mean": self.mean.tolist(),
                                                    "std": self.std.tolist(), "threshold": self.threshold,
                                                    "hidden": AE_HIDDEN, "quantile": AE_QUANTILE})


# ---------------------------------------------------------------- re-fit the attack model
def local_mixed_streams(local: list[pd.DataFrame], cic_stream: pd.DataFrame, rng) -> list[pd.DataFrame]:
    """Every local normal file (time order) + CICIoT2023 attack slices inserted as bursts and solo attacks."""
    att = cic_stream[cic_stream["category"] != tc.NORMAL]
    by_cls = {c: d.reset_index(drop=True) for c, d in att.groupby("cls", sort=True)}
    out = []
    for d in local:
        if not len(d):
            continue
        per = max(1, int(MIX_ATTACK_SHARE * len(d) / max(len(by_cls), 1)))
        parts = {"__local__": [d.assign(cls="__local__")]}
        cc = {"__local__": tc.NORMAL}
        for c, a in by_cls.items():
            s = int(rng.integers(0, len(a) - per)) if len(a) > per else 0
            parts[c] = [a.iloc[s:s + per]]
            cc[c] = a["category"].iloc[0]
        out.append(tc.build_stream(parts, cc, rng, tc.SOLO_SHARE))
    return out


def calibrate(local_train: list[pd.DataFrame], local_val: list[pd.DataFrame], base_run: Path, out_dir: Path,
              log, model_types=("BAL_MS", "FLAT")) -> tuple[dict, AutoencoderBaseline, dict]:
    """local_*: one DataFrame of CICIoT2023 rows per local normal file, in time order (windows per file)."""
    import lightgbm as lgb
    t0 = time.time()
    cfg = json.loads((base_run / "config.json").read_text(encoding="utf-8"))
    log.info("calibration: rebuilding the CICIoT2023 training data like %s (rows/class %s, benign %s)",
             base_run.name, f"{cfg['rows_per_class']:,}", f"{cfg['benign_rows']:,}")
    parts, features, class_cat, _ = tc.load_data(Path(cfg["data"]), cfg["rows_per_class"], cfg["benign_rows"], log)
    base = [f for f in features if f not in cfg.get("drop", [])]
    wfeats = [f for f in tc.WINDOW_FEATURES if f in base]
    cats = [tc.NORMAL] + [c for c in tc.ALL_CATEGORIES if c in set(class_cat.values())]
    streams = {s: tc.build_stream(parts[s], class_cat, np.random.default_rng(SEED + k), tc.SOLO_SHARE)
               for k, s in enumerate(("train", "val"))}
    del parts
    n_lt, n_lv = sum(len(d) for d in local_train), sum(len(d) for d in local_val)
    log.info("calibration: CICIoT2023 train %s + val %s rows | local normal train %s + val %s rows",
             f"{len(streams['train']):,}", f"{len(streams['val']):,}", f"{n_lt:,}", f"{n_lv:,}")

    models = {}
    info = {"local_train_rows": n_lt, "local_val_rows": n_lv, "local_weight": LOCAL_WEIGHT,
            "mix_attack_share": MIX_ATTACK_SHARE}
    normal_id = cats.index(tc.NORMAL)
    mixed = {"train": local_mixed_streams(local_train, streams["train"], np.random.default_rng(SEED + 11)),
             "val": local_mixed_streams(local_val, streams["val"], np.random.default_rng(SEED + 12))}
    log.info("calibration: local mixed streams (local normal + %.0f%% CICIoT2023 attack rows): train %s, val %s rows",
             100 * MIX_ATTACK_SHARE, f"{sum(len(s) for s in mixed['train']):,}",
             f"{sum(len(s) for s in mixed['val']):,}")
    for mt in model_types:
        def xy(stream, local_streams):
            Xs = [tc.build_X(stream, base, wfeats, mt)] + [tc.build_X(s, base, wfeats, mt) for s in local_streams]
            ys = [stream["category"].map(cats.index).to_numpy()] + \
                 [s["category"].map(cats.index).to_numpy() for s in local_streams]
            loc = [np.zeros(len(stream), bool)] + [(s["cls"] == "__local__").to_numpy() for s in local_streams]
            X, y, is_local = pd.concat(Xs, ignore_index=True), np.concatenate(ys), np.concatenate(loc)
            w = tc.class_weights(y, len(cats)) * np.where(is_local, LOCAL_WEIGHT, 1.0)
            return X, y, w, is_local
        Xtr, ytr, wtr, _ = xy(streams["train"], mixed["train"])
        Xva, yva, wva, loc = xy(streams["val"], mixed["val"])
        in_local_stream = np.concatenate([np.zeros(len(streams["val"]), bool)] +
                                         [np.ones(len(s), bool) for s in mixed["val"]])
        params = {**tc.LGB_PARAMS, "num_class": len(cats), "num_threads": os.cpu_count() or 4}
        t1 = time.time()
        booster = lgb.train(params, lgb.Dataset(Xtr, ytr, weight=wtr),
                            tc.NUM_ROUNDS, valid_sets=[lgb.Dataset(Xva, yva, weight=wva)], valid_names=["val"],
                            callbacks=[lgb.early_stopping(tc.EARLY_STOP, verbose=False), lgb.log_evaluation(200)])
        name = f"{mt}_cal"
        mdir = out_dir / "models" / name
        mdir.mkdir(parents=True, exist_ok=True)
        booster.save_model(str(mdir / "model.txt"), num_iteration=booster.best_iteration)
        meta = {"model": mt, "inputs": list(Xtr.columns), "base_features": base, "window_features": wfeats,
                "categories": cats, "calibrated": True, "base_run": str(base_run), "local_weight": LOCAL_WEIGHT}
        tc.write_json(mdir / "features.json", meta)
        # held-out check: local normal rows (false alarms) and CIC attacks hidden inside local normal (detection)
        p = booster.predict(Xva, num_iteration=booster.best_iteration).argmax(1)
        att_in_local = in_local_stream & (yva != normal_id)
        fa_local = float((p[loc] != normal_id).mean()) if loc.any() else float("nan")
        det_local = float((p[att_in_local] != normal_id).mean()) if att_in_local.any() else float("nan")
        info[name] = {"best_iteration": booster.best_iteration, "train_seconds": round(time.time() - t1, 1),
                      "false_alarms_on_held_out_local_normal": fa_local,
                      "detection_of_attacks_inside_held_out_local_normal": det_local}
        log.info("calibration: %s trained in %.0f s (best iteration %d) | held-out local normal: false alarms %.2f%%, "
                 "attacks hidden inside it detected %.2f%%", name, time.time() - t1, booster.best_iteration,
                 100 * fa_local, 100 * det_local)
        models[name] = (lgb.Booster(model_file=str(mdir / "model.txt")), meta)

    ae = AutoencoderBaseline(base)
    info["autoencoder"] = ae.fit(pd.concat(local_train, ignore_index=True), pd.concat(local_val, ignore_index=True), log)
    ae.save(out_dir / "models" / "AUTOENCODER")
    info["seconds"] = round(time.time() - t0, 1)
    tc.write_json(out_dir / "calibration.json", info)
    return models, ae, info
