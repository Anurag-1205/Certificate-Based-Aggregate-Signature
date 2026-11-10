"""Run the final talk's two live demos for real and render their output as screenshots.

    .venv/bin/python presentation/build/make_demo_fallback_final.py

Outputs presentation/demo_fallback_final/*.png. The text is the actual stdout
of each command, split into slide-sized pieces; nothing is edited.
"""
import pathlib
import re
import subprocess

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "presentation" / "demo_fallback_final"
OUT.mkdir(exist_ok=True)
MONO = "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"
FS = 30
FONT = ImageFont.truetype(MONO, FS)
CW = FONT.getlength("M")
BG, FG, MUTE, GREEN, RED = "#101923", "#DDE5EE", "#8FA1B3", "#7BD88F", "#FF8F85"
BAD = ("UNIVERSAL FORGERY", "KEYS STOLEN", "FORGERY SUCCEEDED")
TOKENS = re.compile(r"(UNIVERSAL FORGERY|KEYS STOLEN|FORGERY SUCCEEDED|refused|PASSED|passed|True|False)")
ATTACKER_WINS = ("forged", "forgery", "recovered", "recovers", "succeeds")


def run(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        raise SystemExit(f"{cmd!r} failed:\n{r.stdout}{r.stderr}")
    return r.stdout.splitlines()


def colour(line):
    """Red where the attacker wins, green where the scheme or a test holds."""
    out, i = [], 0
    for m in TOKENS.finditer(line):
        out.append((line[i:m.start()], FG))
        w = m.group(0)
        attacker = w in BAD or (w == "True" and any(k in line for k in ATTACKER_WINS))
        out.append((w, RED if attacker else GREEN))
        i = m.end()
    out.append((line[i:], FG))
    return out


def render(title, lines, name):
    lines = [l for l in lines if l.strip() and set(l.strip()) != {"="}]
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
    path = OUT / name
    im.save(path)
    print("wrote", path.relative_to(ROOT), im.size)


def between(lines, start, stop=None):
    a = next(i for i, l in enumerate(lines) if start in l)
    b = next((i for i, l in enumerate(lines) if i > a and stop and stop in l), len(lines))
    return lines[a:b]


# ---- Demo 1: key-only forgery (make attack, Target 3)
attack = run(".venv/bin/python -m cbas.sidebyside")
render("make attack     # Target 3", between(attack, "TARGET 3", "SUMMARY"), "final_demo1_keyonly.png")

# ---- Demo 1 backup: the 2x2 ablation as tests, both backends
py = ".venv/bin/python -m pytest -p no:cacheprovider tests/test_keyonly_attack.py -k ablation -vv"
tests = [re.sub(r"^tests/test_keyonly_attack.py::", "", l) for l in run(py)
         if "::" in l or (l.startswith("=") and "passed" in l)]
tests = [re.sub(r"\s+\[\s*\d+%\]$", "", l) for l in tests]
render("pytest tests/test_keyonly_attack.py -k ablation -vv", tests, "final_demo1_matrix.png")

# ---- Demo 2: nonce reuse (make nonce), attack then defence
nonce = run(".venv/bin/python -m cbas.nonce_demo")
render("make nonce      # steps 1-3", between(nonce, "STEP 1", "STEP 4"), "final_demo2_attack.png")
render("make nonce      # step 4 and summary", between(nonce, "STEP 4"), "final_demo2_defence.png")
