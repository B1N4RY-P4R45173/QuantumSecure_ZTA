"""
GPU check: logs Python version, torch version, torch.cuda.is_available()
and the name/memory of every GPU, and runs a tiny matmul on each GPU.

Output: runs/gpu_check_<YYYYMMDD_HHMMSS>/
  run.log       all printed output and errors (with timestamps)
  results.json  what was found
  config.json   settings used
"""

from __future__ import annotations

import json
import logging
import platform
import random
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

# ---- settings ----
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = PROJECT_ROOT / "runs"
SEED = 42
TEST_MATRIX_SIZE = 1024  # size of the small matmul run on each GPU

SCRIPT_NAME = "gpu_check"


def setup_run_dir() -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / f"{SCRIPT_NAME}_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def setup_logging(run_dir: Path) -> logging.Logger:
    log = logging.getLogger(SCRIPT_NAME)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    for handler in (logging.FileHandler(run_dir / "run.log", encoding="utf-8"),
                    logging.StreamHandler(sys.stdout)):
        handler.setFormatter(fmt)
        log.addHandler(handler)
    return log


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main() -> int:
    run_dir = setup_run_dir()
    log = setup_logging(run_dir)
    start = time.time()

    config = {
        "script": SCRIPT_NAME,
        "seed": SEED,
        "test_matrix_size": TEST_MATRIX_SIZE,
        "run_dir": str(run_dir),
    }
    write_json(run_dir / "config.json", config)

    results: dict = {"status": "error"}
    try:
        random.seed(SEED)
        log.info("Run folder: %s", run_dir)
        log.info("Settings: %s", config)

        results["python_version"] = sys.version.replace("\n", " ")
        results["python_executable"] = sys.executable
        results["platform"] = platform.platform()
        log.info("Python version: %s", results["python_version"])
        log.info("Python executable: %s", results["python_executable"])
        log.info("Platform: %s", results["platform"])

        import torch

        torch.manual_seed(SEED)
        results["torch_version"] = torch.__version__
        results["torch_cuda_build"] = torch.version.cuda
        results["cuda_available"] = torch.cuda.is_available()
        log.info("torch version: %s (built for CUDA %s)",
                 results["torch_version"], results["torch_cuda_build"])
        log.info("torch.cuda.is_available(): %s", results["cuda_available"])

        gpus = []
        if results["cuda_available"]:
            torch.cuda.manual_seed_all(SEED)
            count = torch.cuda.device_count()
            log.info("GPU count: %d", count)
            for i in range(count):
                props = torch.cuda.get_device_properties(i)
                gpu = {
                    "index": i,
                    "name": props.name,
                    "total_memory_gb": round(props.total_memory / 1024**3, 2),
                    "compute_capability": f"{props.major}.{props.minor}",
                }
                # Tiny matmul to prove the GPU can actually run work.
                t0 = time.time()
                a = torch.randn(TEST_MATRIX_SIZE, TEST_MATRIX_SIZE, device=f"cuda:{i}")
                b = (a @ a).sum().item()
                torch.cuda.synchronize(i)
                gpu["matmul_ok"] = b == b  # False only if result is NaN
                gpu["matmul_seconds"] = round(time.time() - t0, 4)
                gpus.append(gpu)
                log.info("GPU %d: %s | %.2f GB | compute %s | matmul ok=%s in %.4fs",
                         i, gpu["name"], gpu["total_memory_gb"],
                         gpu["compute_capability"], gpu["matmul_ok"],
                         gpu["matmul_seconds"])
        else:
            log.warning("CUDA is NOT available - torch will run on CPU only.")
        results["gpus"] = gpus
        results["gpu_count"] = len(gpus)
        results["status"] = "ok"
    except Exception:
        results["error"] = traceback.format_exc()
        log.error("Run failed:\n%s", results["error"])

    results["time_taken_s"] = round(time.time() - start, 3)
    write_json(run_dir / "results.json", results)

    if results["status"] == "ok":
        log.info("FINISHED OK")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
