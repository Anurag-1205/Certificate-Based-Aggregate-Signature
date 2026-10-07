"""Run the three demo commands for real and render their captured output as screenshots.

    .venv/bin/python presentation/build/make_demo_fallback.py

Outputs presentation/demo_fallback/{demo1_target1,demo2_target2,demo3_ablation}.png
The text is the actual stdout of each command; only the very long pytest test ids are shortened with an ellipsis.
"""
import pathlib
import re
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "presentation" / "demo_fallback"
OUT.mkdir(exist_ok=True)
MONO = "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"
FS = 30
FONT = ImageFont.truetype(MONO, FS)
CW = FONT.getlength("M")
BG, FG, MUTE, GREEN, RED = "#101923", "#DDE5EE", "#8FA1B3", "#7BD88F", "#FF8F85"


def run(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=ROOT)
    return (r.stdout + r.stderr).splitlines()


def colour(line):
    out, i = [], 0
    pat = re.compile(r"(True|False|PASSED|passed|FORGERY SUCCEEDED)")
    for m in pat.finditer(line):
        out.append((line[i:m.start()], FG))
        w = m.group(0)
        out.append((w, RED if w == "FORGERY SUCCEEDED" or (w == "True" and "forged" in line) or (w == "True" and "survives" in line)
                    else GREEN))
        i = m.end()
    out.append((line[i:], FG))
    return out


def render(title, lines, path, maxchars=None):
    if maxchars:
        lines = [l if len(l) <= maxchars else l[:maxchars - 40] + " … " + l[-34:] for l in lines]
    w = int(max(len(title) + 2, *(len(l) for l in lines)) * CW + 70)
    h = int((len(lines) + 2.6) * (FS * 1.35) + 40)
    im = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(im)
    y = 24
    d.text((34, y), "$ " + title, font=FONT, fill=MUTE)
    y += FS * 1.35 * 1.6
    for l in lines:
        x = 34
        for seg, c in colour(l):
            d.text((x, y), seg, font=FONT, fill=c)
            x += FONT.getlength(seg)
        y += FS * 1.35
    im.save(path)
    print("wrote", path.relative_to(ROOT), im.size)


# ---- make attack (Target 1 and Target 2 blocks, exactly as printed)
out = run("make attack")
t1 = next(i for i, l in enumerate(out) if "TARGET 1" in l)
t2 = next(i for i, l in enumerate(out) if "TARGET 2" in l)
sm = next(i for i, l in enumerate(out) if l.strip() == "SUMMARY")
block1 = [l for l in out[t1:t2 - 2] if set(l.strip()) != {"="} and l.strip()]
block2 = [l for l in out[t2:sm - 2] if set(l.strip()) != {"="} and l.strip()]
render("make attack     # Target 1", block1, OUT / "demo1_target1.png")
render("make attack     # Target 2", block2, OUT / "demo2_target2.png")

# ---- ablation tests
py = ".venv/bin/python -m pytest -p no:cacheprovider tests/test_forgery.py -k ablat -vv"
pt = [l for l in run(py) if l.strip() and not l.startswith("=====") or l.startswith("=====") and "passed" in l]
pt = [l for l in pt if not l.startswith(("platform", "rootdir", "configfile", "plugins", "collected", "hypothesis", "cachedir"))]
render(".venv/bin/python -m pytest tests/test_forgery.py -k ablat -vv", pt, OUT / "demo3_ablation.png", maxchars=118)
