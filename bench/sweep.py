"""Aggregate-verification cost as a function of the number of signers.

Measures both schemes across a sweep of ``n`` and fits a line to each.  The
slope is the quantity of interest: it is what the operation counts predict, and
unlike the intercept it is insensitive to fixed per-call overheads.

Every workload -- both schemes at every ``n``, plus the Ed25519 reference -- is
timed inside a single interleaved run, after the CPU has been driven to a steady
clock.  Interleaving across schemes matters as much as across ``n``: the
headline result is a *ratio* between two schemes, so any clock change must be
prevented from landing on one scheme and not the other.

Fleets are built once at the largest ``n`` and prefixes reused, keeping setup
out of the measured region.
"""

from __future__ import annotations

from dataclasses import dataclass

from cbas import scheme as fixed
from cbas import verma
from cbas.backend import BACKENDS, CountingBackend, SodiumBackend

from .baseline import Ed25519
from .harness import measure_many, stabilize

DEFAULT_NS = [50, 100, 150, 200, 250, 300, 350, 400, 450, 500]


@dataclass
class SweepPoint:
    n: int
    agg_verify_ms: float
    agg_verify_iqr: float
    ops_Te: int
    ops_Ta: int
    ops_Th: int


@dataclass
class SweepResult:
    cbas: list[SweepPoint]
    verma: list[SweepPoint]
    ed25519: list[tuple[int, float]]
    stabilisation: dict
    backend: str = "ristretto255"


def _build_fixed(be, n):
    params, msk = fixed.setup(be, b"epoch-0")
    signers, sigs, messages = [], [], []
    for i in range(n):
        ident = f"sensor-{i:04d}".encode()
        keys = fixed.keygen(params)
        cert = fixed.cert_gen(params, msk, ident, keys.pk)
        signer = fixed.Signer(identity=ident, pk=keys.pk, R=cert.R)
        m = f"temp={20 + i % 15}.5C;seq={i}".encode()
        signers.append(signer)
        messages.append(m)
        sigs.append(fixed.sign(params, signer, keys.sk, cert, m))
    return params, signers, messages, sigs


def _build_verma(be, n):
    params, msk = verma.setup(be, b"epoch-0")
    signers, sigs, messages = [], [], []
    for i in range(n):
        ident = f"sensor-{i:04d}".encode()
        keys = verma.keygen(params)
        cert = verma.cert_gen(params, msk, ident, keys.pk)
        signer = verma.Signer(identity=ident, pk=keys.pk)
        m = f"temp={20 + i % 15}.5C;seq={i}".encode()
        signers.append(signer)
        messages.append(m)
        sigs.append(verma.sign(params, signer, keys.sk, cert, m))
    return params, signers, messages, sigs


def _count_ops(scheme_mod, build_fn, n, backend_cls=SodiumBackend):
    """Operation counts for one aggregate verification at this ``n``."""
    counting = CountingBackend(backend_cls())
    params, signers, messages, sigs = build_fn(counting, n)
    agg = scheme_mod.agg_sign(params, sigs)
    with counting.count() as c:
        assert scheme_mod.agg_verify(params, signers, messages, agg)
    return c.Te, c.Ta, c.Th


def run_sweep(ns=DEFAULT_NS, rounds: int = 7, backend: str = "ristretto255") -> SweepResult:
    backend_cls = BACKENDS[backend]
    be = backend_cls()
    stab = stabilize(be)

    max_n = max(ns)
    fp, fsigners, fmessages, fsigs = _build_fixed(be, max_n)
    vp, vsigners, vmessages, vsigs = _build_verma(be, max_n)

    ed = Ed25519(SodiumBackend())
    ed_pk, ed_sk = ed.keypair()
    ed_msgs = [f"temp={20 + i % 15}.5C;seq={i}".encode() for i in range(max_n)]
    ed_sigs = [ed.sign(m, ed_sk) for m in ed_msgs]

    tasks = {}
    for n in ns:
        f_agg = fixed.agg_sign(fp, fsigs[:n])
        v_agg = verma.agg_sign(vp, vsigs[:n])
        f_signers, f_messages = fsigners[:n], fmessages[:n]
        v_signers, v_messages = vsigners[:n], vmessages[:n]

        tasks[f"cbas:{n}"] = (
            lambda p=fp, s=f_signers, m=f_messages, a=f_agg: fixed.agg_verify(p, s, m, a)
        )
        tasks[f"verma:{n}"] = (
            lambda p=vp, s=v_signers, m=v_messages, a=v_agg: verma.agg_verify(p, s, m, a)
        )

        def ed_verify_n(count=n):
            for i in range(count):
                ed.verify(ed_sigs[i], ed_msgs[i], ed_pk)

        tasks[f"ed25519:{n}"] = ed_verify_n

    results = measure_many(tasks, rounds=rounds)

    cbas_pts, verma_pts, ed_pts = [], [], []
    for n in ns:
        te, ta, th = _count_ops(fixed, _build_fixed, n, backend_cls)
        r = results[f"cbas:{n}"]
        cbas_pts.append(SweepPoint(n, r.median_ms, r.iqr_ms, te, ta, th))

        te, ta, th = _count_ops(verma, _build_verma, n, backend_cls)
        r = results[f"verma:{n}"]
        verma_pts.append(SweepPoint(n, r.median_ms, r.iqr_ms, te, ta, th))

        ed_pts.append((n, results[f"ed25519:{n}"].median_ms))

    return SweepResult(cbas_pts, verma_pts, ed_pts, stab, backend)
