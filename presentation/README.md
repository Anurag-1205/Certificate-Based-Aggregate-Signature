# Interim presentation: CBAS audit

Untracked working folder. Nothing under `src/`, `tests/` or `bench/` was modified.

| File | What it is |
|---|---|
| `CBAS_Interim_Presentation.pptx` | The deck: 32 main slides (the last one lists the work remaining for the final presentation), a Thank You slide (the talk ends there), an appendix divider, backup slides B1-B12. Speaker notes on every slide; 12 small presenter cues. |
| `CBAS_Interim_Presentation.pdf` | PDF export of the slides (rendered with LibreOffice; notes not included). |
| `speaker_notes.md` | Every slide's speaker notes in one file, with the 18-question Q&A preparation under slide 31. |
| `demo_fallback/` | Screenshots of the real captured output of the three demos (also on backup slides B11, B12). |
| `figures/` | Five quantitative figures, each with its own source line. |
| `data/claims.json`, `data/audit_checks.json` | Every number used in the deck, computed from the code and the tracked benchmark JSON. |
| `audit/verify_claims.py` | Recomputes and asserts all counts, costs, test totals and timing ratios. |
| `audit/dagger_checks.py` | Audit-only checks that are not repository tests (backup B6, B8, B9 and the P-256 note). |
| `build/` | The deck builder (python-pptx), figure script, QC script, render script. |

## Rebuild

```bash
python3 -m venv /tmp/deckenv && /tmp/deckenv/bin/pip install python-pptx pillow
.venv/bin/python presentation/audit/verify_claims.py      # asserts every number
.venv/bin/python presentation/audit/dagger_checks.py      # about one minute (timing)
.venv/bin/python presentation/build/make_figures.py
.venv/bin/python presentation/build/make_demo_fallback.py   # runs the demos, renders captured output
/tmp/deckenv/bin/python presentation/build/build_deck.py            # add --no-cues to omit the presenter cues
/tmp/deckenv/bin/python presentation/build/qc.py          # notes, stray markup, off-slide shapes
presentation/build/render.sh 110                          # PDF and per-slide PNGs in render/
```

Fonts: Calibri, Cambria, Courier New. The PDF was rendered with metric-compatible substitutes (Carlito, Caladea, Liberation Mono).
