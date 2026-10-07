"""Assemble the deck.

    /path/to/deckenv/bin/python presentation/build/build_deck.py

Writes presentation/CBAS_Interim_Presentation.pptx and prints layout warnings.
"""
import importlib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import lib  # noqa: E402

OUT = HERE.parent / "CBAS_Interim_Presentation.pptx"
PARTS = ["slides_a", "slides_b", "slides_c", "slides_d", "slides_e", "slides_f"]
TOTAL_MAIN = 31


def main():
    if "--no-cues" in sys.argv:
        lib.CUES["on"] = False
    d = lib.Deck(TOTAL_MAIN)
    for name in PARTS:
        if not (HERE / f"{name}.py").exists():
            continue
        importlib.import_module(name).build(d)
    import notes_final
    notes_final.apply(d.prs)
    # presenter cues named PresenterCue_B11 jump to backup slide B11 when clicked in slideshow mode
    b11 = next((sl for sl in d.prs.slides if any(sh.has_text_frame and sh.text_frame.text.startswith("B11 ·") for sh in sl.shapes)), None)
    if b11 is not None:
        for sl in d.prs.slides:
            for sh in sl.shapes:
                if sh.name == "PresenterCue_B11":
                    sh.click_action.target_slide = b11
    d.save(OUT)
    print(f"wrote {OUT} with {d.count} slides")
    if lib.WARN:
        print(f"\n{len(lib.WARN)} layout warnings:")
        for w in lib.WARN:
            print("  ", w)
    else:
        print("no layout warnings")


if __name__ == "__main__":
    main()
