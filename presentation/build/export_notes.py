"""Write the speaker notes to markdown and print the per-tag slide lists.

    export_notes.py                 interim deck -> presentation/speaker_notes.md
    export_notes.py Final 31        final deck (Thank You is slide 31) -> presentation/speaker_notes_final.md
"""
import collections
import pathlib
import re
import sys

from pptx import Presentation

ROOT = pathlib.Path(__file__).resolve().parents[2]
DECK = sys.argv[1] if len(sys.argv) > 1 else "Interim"
THANKS = int(sys.argv[2]) if len(sys.argv) > 2 else 28
prs = Presentation(str(ROOT / "presentation" / f"CBAS_{DECK}_Presentation.pptx"))
TAGS = ["PAPER", "REPRODUCED", "IMPLEMENTATION", "EXPERIMENT", "OUR AUDIT", "OUR FINDING"]
out = [f"# Speaker notes: CBAS {DECK.lower()} presentation\n"]
bytag = collections.defaultdict(list)
for i, sl in enumerate(prs.slides, 1):
    texts = [(sh.top, sh.left, sh.text_frame.text) for sh in sl.shapes if sh.has_text_frame and sh.text_frame.text.strip()]
    tags = [t for top, left, t in texts if t in TAGS and top < 600000]
    title = next((t for top, left, t in sorted(texts) if 450000 < top < 700000 and t not in TAGS), "(title or divider slide)")
    title = {1: "Title slide", THANKS: "Thank you (the talk ends here)",
             THANKS + 1: "Appendix divider (backup, only if asked)"}.get(i, title)
    label = next((m.group(1) for _, _, tx in texts if (m := re.fullmatch(r"Backup (B\d+)", tx.strip()))), None)
    num = label if label else str(i)
    for t in tags:
        bytag[t].append(num)
    out.append(f"\n## Slide {num}: {title}\n")
    if tags:
        out.append(f"Tags: {', '.join(tags)}\n")
    out.append((sl.notes_slide.notes_text_frame.text if sl.has_notes_slide else "") + "\n")
name = "speaker_notes.md" if DECK == "Interim" else f"speaker_notes_{DECK.lower()}.md"
(ROOT / "presentation" / name).write_text("\n".join(out))
for t in TAGS:
    print(f"{t:<15} {', '.join(bytag[t])}")
print("\nwords in notes:", sum(len(o.split()) for o in out))
