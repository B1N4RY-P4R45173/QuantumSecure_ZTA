"""
Speed and resource measurement (tests E2 and E4).

  * PeakMemory   - highest RAM (RSS) of this process while the block runs
  * timed        - wall-clock seconds of a block
  * latency_ms   - median time to classify ONE input (like an inline device would)
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager

import numpy as np
import psutil


class PeakMemory:
    def __init__(self, interval: float = 0.05):
        self.interval = interval
        self.peak_mb = 0.0
        self._stop = threading.Event()
        self._proc = psutil.Process()

    def _run(self):
        while not self._stop.is_set():
            self.peak_mb = max(self.peak_mb, self._proc.memory_info().rss / 2**20)
            time.sleep(self.interval)

    def __enter__(self):
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._t.join()
        self.peak_mb = max(self.peak_mb, self._proc.memory_info().rss / 2**20)


@contextmanager
def timed(store: dict, key: str):
    t0 = time.perf_counter()
    yield
    store[key] = time.perf_counter() - t0


def latency_ms(predict_one, samples, repeats: int = 300) -> float:
    """Median milliseconds for one prediction. `samples` is a list of single inputs."""
    for s in samples[:20]:                       # warm-up
        predict_one(s)
    times = []
    for i in range(repeats):
        s = samples[i % len(samples)]
        t0 = time.perf_counter()
        predict_one(s)
        times.append((time.perf_counter() - t0) * 1000)
    return float(np.median(times))
