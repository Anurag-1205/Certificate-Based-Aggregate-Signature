"""Assemble the final deck.

    /path/to/deckenv/bin/python presentation/build/build_final.py [--no-cues]

Writes presentation/CBAS_Final_Presentation.pptx and prints layout warnings.
Reads presentation/data/claims_final.json (run audit/verify_claims_final.py first).
"""
import importlib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import lib  # noqa: E402

OUT = HERE.parent / "CBAS_Final_Presentation.pptx"
PARTS = ["final_a", "final_b", "final_c", "final_d", "final_e", "final_f"]
TOTAL_MAIN = 30
FOOTER = "Certificate-based aggregate signatures for IIoT · final research presentation"

# Seconds per main slide. Total is printed by the build and must stay within the 15-20 minute slot.
ROUTE = {1: 20, 2: 20, 3: 40, 4: 30, 5: 30, 6: 25, 7: 30, 8: 60, 9: 30, 10: 75, 11: 30, 12: 60, 13: 20,
         14: 30, 15: 45, 16: 30, 17: 30, 18: 30, 19: 45, 20: 30, 21: 45, 22: 75, 23: 30, 24: 30, 25: 35,
         26: 20, 27: 30, 28: 20, 29: 20, 30: 30}


def apply_route(prs):
    """Replace each main slide's TIME line with the route, and record the running clock."""
    clock = 0
    for i, sl in enumerate(prs.slides, 1):
        if i > TOTAL_MAIN:
            break
        clock += ROUTE[i]
        tf = sl.notes_slide.notes_text_frame
        lines, advice = [], ""
        for l in tf.text.split("\n"):
            if l.startswith("TIME:"):
                advice = l.split(". ", 1)[1] if ". " in l else ""
            else:
                lines.append(l)
        lines.append(f"TIME: {ROUTE[i]} s on this slide; {clock // 60}:{clock % 60:02d} elapsed at the end of it. {advice}".rstrip())
        tf.text = "\n".join(lines)
    return clock


def main():
    if "--no-cues" in sys.argv:
        lib.CUES["on"] = False
    d = lib.Deck(TOTAL_MAIN, footer=FOOTER)
    for name in PARTS:
        if (HERE / f"{name}.py").exists():
            importlib.import_module(name).build(d)
    total = apply_route(d.prs)
    d.save(OUT)
    print(f"wrote {OUT} with {d.count} slides; spoken route {total // 60}:{total % 60:02d}")
    if lib.WARN:
        print(f"\n{len(lib.WARN)} layout warnings:")
        for w in lib.WARN:
            print("  ", w)
    else:
        print("no layout warnings")


if __name__ == "__main__":
    main()
