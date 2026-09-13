"""Build the self-contained Kaggle kernel used for the second-machine check.

RESULTS.md lists "single machine" as a limitation of the timing evidence. This
packages ``src/`` and ``bench/`` into a single script that can be pushed to
Kaggle and run on unrelated hardware, so the sweep, the self-test and the
forgery demonstration all execute somewhere this project does not control.

    python -m bench.kaggle.build_kernel          # writes build/ next to this file
    kaggle kernels push -p bench/kaggle/build

CPU only: the workload is sequential 255-bit modular arithmetic, so a GPU and
fp16 have nothing to contribute. The kernel metadata sets ``enable_gpu: false``
deliberately.
"""

from __future__ import annotations

import base64
import io
import json
import pathlib
import tarfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BUILD = HERE / "build"

KERNEL_ID = "anuragkaushal183/cbas-phase2-bench"

TEMPLATE = '''"""CBAS Phase 2 benchmark, run on Kaggle for a second-machine confirmation."""
import base64, io, os, platform, subprocess, sys, tarfile

PAYLOAD = "@@PAYLOAD@@"

os.makedirs("/kaggle/working/proj", exist_ok=True)
os.chdir("/kaggle/working/proj")
tarfile.open(fileobj=io.BytesIO(base64.b64decode(PAYLOAD))).extractall(".")
sys.path.insert(0, os.path.abspath("src"))
sys.path.insert(0, os.path.abspath("."))

import ctypes.util
if not ctypes.util.find_library("sodium"):
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pynacl"], check=False)

R = "=" * 74
print(R); print("  ENVIRONMENT"); print(R)
print("  platform :", platform.platform())
print("  python   :", platform.python_version())
try:
    for line in open("/proc/cpuinfo"):
        if line.startswith("model name"):
            print("  cpu      :", line.split(":", 1)[1].strip()); break
except OSError:
    pass
print("  cores    :", os.cpu_count())
try:
    print("  governor :", open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read().strip())
except OSError:
    print("  governor : not exposed (virtualised)")

from cbas.backend import BACKENDS, CountingBackend, SodiumBackend, OpenSSLBackend
print("  libsodium:", SodiumBackend().libsodium_version)
print("  openssl  :", OpenSSLBackend().openssl_version)
print()

print(R); print("  BACKEND SELF-TEST"); print(R)
from cbas.backend import selftest
if selftest.main() != 0:
    print("SELF-TEST FAILED - everything below is meaningless"); sys.exit(1)
print()

print(R); print("  FORGERY CHECK"); print(R)
from cbas import sidebyside
sidebyside.main()
print()

print(R); print("  OPERATION COUNTS, BOTH BACKENDS"); print(R)
from cbas import scheme as fixed, verma
from bench.sweep import _build_fixed, _build_verma
for bname, cls in sorted(BACKENDS.items()):
    for label, mod, build in (("CBAS", fixed, _build_fixed), ("Verma", verma, _build_verma)):
        cb = CountingBackend(cls()); n = 40
        p, s, m, sg = build(cb, n)
        agg = mod.agg_sign(p, sg)
        with cb.count() as c:
            assert mod.agg_verify(p, s, m, agg)
        print(f"  {cls().name:<24} {label:<6} n={n}: {c.formula(n)}")
print()

print(R); print("  REPEATED TIMING SWEEPS"); print(R)
from bench.repeat import main as repeat_main
sys.argv = ["repeat", "--repeats", "3", "--tag", "kaggle-xeon"]
repeat_main()

import shutil, glob
for f in glob.glob("/kaggle/working/proj/bench/results/*.json"):
    shutil.copy(f, "/kaggle/working/")
    print("  copied", os.path.basename(f))
'''


def build() -> pathlib.Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for top in ("src", "bench"):
            for path in sorted((ROOT / top).rglob("*")):
                if (path.is_dir() or "__pycache__" in path.parts
                        or "egg-info" in str(path) or path.suffix == ".pyc"
                        or "/out/" in str(path) or "/build/" in str(path)):
                    continue
                tf.add(path, arcname=str(path.relative_to(ROOT)))
    payload = base64.b64encode(buf.getvalue()).decode()
    script = TEMPLATE.replace("@@PAYLOAD@@", payload)
    compile(script, "cbas_bench.py", "exec")   # fail here, not on Kaggle

    BUILD.mkdir(exist_ok=True)
    (BUILD / "cbas_bench.py").write_text(script)
    (BUILD / "kernel-metadata.json").write_text(json.dumps({
        "id": KERNEL_ID,
        "title": KERNEL_ID.split("/")[-1],
        "code_file": "cbas_bench.py",
        "language": "python",
        "kernel_type": "script",
        "is_private": True,
        "enable_gpu": False,
        "enable_internet": True,
        "dataset_sources": [],
        "competition_sources": [],
        "kernel_sources": [],
    }, indent=2))
    return BUILD


if __name__ == "__main__":
    out = build()
    size = (out / "cbas_bench.py").stat().st_size
    print(f"built {out}/cbas_bench.py ({size / 1024:.1f} KB)")
    print(f"push with:  kaggle kernels push -p {out.relative_to(ROOT)}")
