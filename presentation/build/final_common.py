"""Shared helpers and verified data for the final deck's slide modules."""
import json
import pathlib
import textwrap

import theme as T
from lib import box, pill, tb

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIG = ROOT / "presentation" / "figures"
DEMO = ROOT / "presentation" / "demo_fallback_final"
C = json.loads((ROOT / "presentation" / "data" / "claims_final.json").read_text())


def N(s):
    return textwrap.dedent(s).strip()


def tag_pill(s, x, y, tag, size=10):
    w = 0.16 + 0.092 * len(tag)
    pill(s, x, y, w, 0.26, tag, T.TAGS[tag], size=size)
    return w


def card(s, x, y, w, h, head, body, tag=None, line=T.RULE, fill=T.WHITE, hsize=17, bsize=14.5, lw=1.25, gap=3):
    """A white card with an optional provenance pill, a bold heading and body lines."""
    box(s, x, y, w, h, fill=fill, line=line, lw=lw, radius=0.1)
    yy = y + 0.14
    if tag:
        tag_pill(s, x + 0.18, yy, tag)
        yy += 0.36
    items = [{"text": head, "bold": True, "size": hsize, "after": 4 + gap}]
    items += [{"text": b, "size": bsize, "color": T.MUTED if i else T.INK, "after": gap} for i, b in enumerate(body)]
    tb(s, x + 0.18, yy, w - 0.36, h - (yy - y) - 0.1, items, lsp=0.97)


def quote(s, x, y, w, h, text, source):
    box(s, x, y, w, h, fill=T.PANEL, line=None, radius=0.1)
    box(s, x, y, 0.09, h, fill=T.TAGS["PAPER"], line=None, radius=0)
    tb(s, x + 0.3, y + 0.14, w - 0.5, h - 0.55, f"“{text}”", size=17, font=T.F_MATH, lsp=0.97)
    tb(s, x + 0.3, y + h - 0.42, w - 0.5, 0.3, source, size=12.5, color=T.MUTED)


def verdict(s, x, y, w, text, kind="bad", h=0.5, size=16):
    line, fill = {"bad": (T.BAD, T.BAD_T), "good": (T.GOOD, T.GOOD_T)}[kind]
    box(s, x, y, w, h, fill=fill, line=line, lw=1.5, radius=0.1, text=text, size=size, bold=True, color=line)


def num_badge(s, x, y, n, fill=T.INK, d=0.42):
    box(s, x, y, d, d, fill=fill, line=None, radius=d / 2, text=str(n), size=15, bold=True, color="#FFFFFF")
