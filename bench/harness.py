"""Timing infrastructure.

Measurement hygiene matters more than usual here, because two of the three
operations we care about (``Ta`` at ~5 us and ``Th`` at ~4 us in the paper's own
Table IV) sit close to or below the resolution of a naive Python timer.  Timing
those individually measures the timer, not the operation.

A second hazard proved more serious on the test machine, a 15 W AMD Ryzen 5
7520U under the ``powersave`` governor with boost enabled: the clock ramps by
roughly a factor of two once the core is loaded.  A naive sweep therefore
measured n=100 as *cheaper* than n=50, purely because the processor sped up
between the two data points.  Any sweep that does not control for this produces
a slope that is an artefact of thermal policy.

The approach is therefore:

  * :func:`stabilize` spins on real group operations until the cost of a
    reference operation stops changing, bringing the core to a steady clock
    before anything is recorded;
  * :func:`measure_many` interleaves the workloads, timing every one of them in
    each round and taking the median across rounds, so that any residual clock
    change affects all data points alike instead of correlating with ``n``;
  * a repetition count is auto-calibrated so each sample spans at least
    ``min_time`` seconds, and divided out;
  * results are reported as the **median**, since these operations have long
    tails from allocation and garbage collection that make the mean
    unrepresentative, with the interquartile range alongside so the spread is
    visible.

What is being measured
----------------------
Wall-clock figures here cover Python plus ctypes marshalling plus libsodium,
not libsodium alone.  That overhead is real but is paid per operation by both
schemes alike, so it inflates absolute timings while largely cancelling in the
ratios and slopes that the analysis actually rests on.  ``ops.py`` measures the
per-operation costs on this machine so that the inflation can be quantified
rather than assumed.
"""

from __future__ import annotations

import gc
import platform
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Measurement:
    """Timing of a single callable, in milliseconds per call."""

    label: str
    median_ms: float
    iqr_ms: float
    min_ms: float
    samples: int
    reps_per_sample: int

    def __str__(self) -> str:
        return f"{self.label}: {self.median_ms:.4f} ms (IQR {self.iqr_ms:.4f}, n={self.samples})"


def measure(
    fn: Callable[[], object],
    label: str = "",
    min_time: float = 0.05,
    samples: int = 9,
    warmup: int = 3,
    max_reps: int = 1_000_000,
) -> Measurement:
    """Time ``fn`` with auto-calibrated repetitions and median reporting."""
    for _ in range(warmup):
        fn()

    # Calibrate: grow the repetition count until one sample spans min_time.
    reps = 1
    while reps < max_reps:
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        elapsed = time.perf_counter() - t0
        if elapsed >= min_time:
            break
        # Extrapolate, with a cap so a single step cannot explode.
        growth = max(2, min(16, int(min_time / max(elapsed, 1e-9))))
        reps *= growth

    timings = []
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(samples):
            t0 = time.perf_counter()
            for _ in range(reps):
                fn()
            timings.append((time.perf_counter() - t0) / reps * 1000.0)
    finally:
        if gc_was_enabled:
            gc.enable()

    timings.sort()
    if len(timings) >= 4:
        q1 = statistics.median(timings[: len(timings) // 2])
        q3 = statistics.median(timings[(len(timings) + 1) // 2:])
        iqr = q3 - q1
    else:  # pragma: no cover
        iqr = timings[-1] - timings[0]

    return Measurement(
        label=label,
        median_ms=statistics.median(timings),
        iqr_ms=iqr,
        min_ms=timings[0],
        samples=len(timings),
        reps_per_sample=reps,
    )


@dataclass
class Environment:
    """Machine and library identification, recorded alongside every result."""

    python: str = field(default_factory=platform.python_version)
    machine: str = field(default_factory=platform.machine)
    system: str = field(default_factory=lambda: f"{platform.system()} {platform.release()}")
    processor: str = ""
    libsodium: str = ""

    def __post_init__(self):
        if not self.processor:
            self.processor = _cpu_model()
        if not self.libsodium:
            try:
                from cbas.backend import SodiumBackend

                self.libsodium = SodiumBackend().libsodium_version
            except Exception:  # pragma: no cover
                self.libsodium = "unknown"

    def as_dict(self) -> dict:
        return {
            "python": self.python,
            "machine": self.machine,
            "system": self.system,
            "processor": self.processor,
            "libsodium": self.libsodium,
        }

    def render(self) -> str:
        return (
            f"  CPU        : {self.processor}\n"
            f"  System     : {self.system} ({self.machine})\n"
            f"  Python     : {self.python}\n"
            f"  libsodium  : {self.libsodium}"
        )


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:  # pragma: no cover
        pass
    return platform.processor() or "unknown"


def stabilize(backend, max_seconds: float = 25.0, min_seconds: float = 4.0,
              tolerance: float = 0.03, streak: int = 3, chunk: int = 2000) -> dict:
    """Drive the CPU to a steady clock before measuring anything.

    Spins on real scalar multiplications until the per-operation cost has been
    stable within ``tolerance`` for ``streak`` consecutive chunks *and* at least
    ``min_seconds`` have elapsed.  Both conditions are needed: on a laptop part
    the clock can hold briefly at an intermediate step before ramping again, so
    a short run can converge on a rate that is not the steady-state one.
    """
    k = backend.scalar_random()
    P = backend.generator
    start = time.perf_counter()
    deadline = start + max_seconds
    prev = None
    stable = 0
    history = []

    while time.perf_counter() < deadline:
        t0 = time.perf_counter()
        for _ in range(chunk):
            backend.point_mul(k, P)
        rate_ms = (time.perf_counter() - t0) / chunk * 1000.0
        history.append(rate_ms)

        if prev is not None and abs(rate_ms - prev) / prev < tolerance:
            stable += 1
        else:
            stable = 0
        prev = rate_ms

        if stable >= streak and (time.perf_counter() - start) >= min_seconds:
            return {"converged": True, "reference_ms": rate_ms,
                    "seconds": time.perf_counter() - start,
                    "iterations": len(history), "history": history}

    return {"converged": False, "reference_ms": prev,
            "seconds": time.perf_counter() - start,
            "iterations": len(history), "history": history}


def _calibrate(fn, min_time: float, max_reps: int) -> int:
    reps = 1
    while reps < max_reps:
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        elapsed = time.perf_counter() - t0
        if elapsed >= min_time:
            return reps
        reps *= max(2, min(16, int(min_time / max(elapsed, 1e-9))))
    return reps  # pragma: no cover


def measure_many(
    tasks: dict,
    rounds: int = 7,
    min_time: float = 0.02,
    warmup: int = 2,
) -> dict:
    """Time several callables in interleaved rounds.

    Every task is timed once per round, and the median across rounds is
    reported.  Interleaving is what makes a sweep trustworthy on a machine
    whose clock moves: a frequency change during the run shifts a whole round
    rather than one value of ``n``, so it cannot masquerade as a trend.
    """
    labels = list(tasks)
    for label in labels:
        for _ in range(warmup):
            tasks[label]()

    reps = {label: _calibrate(tasks[label], min_time, 1_000_000) for label in labels}
    timings = {label: [] for label in labels}

    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(rounds):
            for label in labels:
                fn, r = tasks[label], reps[label]
                t0 = time.perf_counter()
                for _ in range(r):
                    fn()
                timings[label].append((time.perf_counter() - t0) / r * 1000.0)
    finally:
        if gc_was_enabled:
            gc.enable()

    out = {}
    for label in labels:
        ts = sorted(timings[label])
        if len(ts) >= 4:
            q1 = statistics.median(ts[: len(ts) // 2])
            q3 = statistics.median(ts[(len(ts) + 1) // 2:])
            iqr = q3 - q1
        else:
            iqr = ts[-1] - ts[0]
        out[label] = Measurement(label, statistics.median(ts), iqr, ts[0],
                                 len(ts), reps[label])
    return out


def cpu_policy() -> str:
    """Governor and boost state, recorded so readers can judge the numbers."""
    bits = []
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as fh:
            bits.append(f"governor={fh.read().strip()}")
    except OSError:
        pass
    try:
        with open("/sys/devices/system/cpu/cpufreq/boost") as fh:
            bits.append(f"boost={'on' if fh.read().strip() == '1' else 'off'}")
    except OSError:
        pass
    return ", ".join(bits) or "unknown"


def linfit(xs, ys) -> tuple[float, float, float]:
    """Least-squares fit ``y = a*x + b``.  Returns ``(slope, intercept, r2)``."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r2 = 1 - ss_res / ss_tot if ss_tot else 1.0
    return slope, intercept, r2
