"""Tests for the benchmark harness.

Fast checks only: the harness must be correct, but the sweep itself is far too
slow for the test suite and is run separately via `make bench`.
"""

import pytest

from bench.harness import Environment, cpu_policy, linfit, measure, measure_many


def test_linfit_recovers_a_known_line():
    xs = list(range(1, 20))
    slope, intercept, r2 = linfit(xs, [3.5 * x + 7.0 for x in xs])
    assert slope == pytest.approx(3.5, rel=1e-9)
    assert intercept == pytest.approx(7.0, rel=1e-9)
    assert r2 == pytest.approx(1.0, rel=1e-9)


def test_linfit_reports_poor_fit_for_noise():
    xs = [1, 2, 3, 4, 5, 6]
    _, _, r2 = linfit(xs, [5, 1, 6, 2, 7, 1])
    assert r2 < 0.5


def test_measure_returns_sane_values():
    """Basic sanity only.

    Deliberately no cross-workload comparison here. Separate calls to measure()
    are taken at different moments, and this project's own benchmarking found
    the CPU clock ramping by a factor of two between such moments -- which is
    precisely why comparisons go through measure_many() instead. Asserting a
    ratio across two independent measure() calls would be testing the path we
    know to be unreliable, and would be flaky for the same reason the first
    sweep was wrong.
    """
    m = measure(lambda: sum(range(4000)), "work", min_time=0.02, samples=5)
    assert m.median_ms > 0
    assert m.min_ms <= m.median_ms
    assert m.iqr_ms >= 0
    assert m.samples == 5


def test_measure_many_is_interleaved_and_scales():
    """Interleaved measurement is the path comparisons must use.

    Because every workload is timed once per round, a clock change shifts a
    whole round rather than one workload, so relative costs survive it.
    """
    def work(k):
        return lambda: sum(range(k))

    res = measure_many({"a": work(3000), "b": work(6000), "c": work(12000)},
                       rounds=7, min_time=0.02)
    assert set(res) == {"a", "b", "c"}
    assert res["a"].median_ms < res["b"].median_ms < res["c"].median_ms
    assert 1.4 < res["b"].median_ms / res["a"].median_ms < 2.8
    assert 1.4 < res["c"].median_ms / res["b"].median_ms < 2.8


def test_measure_reports_repetition_count():
    m = measure(lambda: sum(range(50)), "tiny", min_time=0.02, samples=3)
    assert m.reps_per_sample > 1, "a sub-microsecond op must be batched"
    assert m.median_ms > 0


def test_environment_is_populated():
    env = Environment()
    assert env.libsodium != "unknown"
    assert env.python
    assert "Te" not in env.render()
    assert isinstance(cpu_policy(), str)


def test_ed25519_baseline_roundtrip():
    from bench.baseline import Ed25519

    ed = Ed25519()
    pk, sk = ed.keypair()
    sig = ed.sign(b"hello", sk)
    assert ed.verify(sig, b"hello", pk)
    assert not ed.verify(sig, b"hellp", pk)
