# Final presentation: presenter guide

The deck is [presentation/CBAS_Final_Presentation.pptx](presentation/CBAS_Final_Presentation.pptx)
(PDF beside it). Speaker notes for every slide, including a timed route, are in the deck and in
[presentation/speaker_notes_final.md](presentation/speaker_notes_final.md).

- **Format:** 30 main slides, then Thank You (slide 31), an appendix divider, and backups B1–B14.
- **Time:** the route in the notes adds up to **17 min 25 s**. That leaves room in a 15–20 minute
  slot for a slow demo or one question mid-talk. Each slide's notes end with a `TIME:` line that
  gives the seconds for that slide and the clock at its end.
- **Demos:** two live demos, on slides 10 and 22. Each demo slide also shows the captured output of
  the same command, so a failed terminal costs nothing.

## Slide map

| Slides | Part | Content | Tags |
|---|---|---|---|
| 1–2 | Opening | Title; roadmap from the interim to today | |
| 3–5 | I · Recap (as the TAs asked) | The repaired scheme's architecture (who computes and sends what, and where Parts III–V land); the paper's attack reproduced, and the T-binding ablation; the cost rows about ×2 too low | PAPER, REPRODUCED, OUR AUDIT, EXPERIMENT |
| 6 | I · Promises | The four open questions from interim slide 27, each answered; the tag legend | |
| 7–13 | II · A second look at the attack | Key-only universal forgery on Verma; it contradicts Table II; **Demo 1**; why the repair resists it; the 2×2; the general lesson | OUR FINDING, EXPERIMENT |
| 14–16 | III · Faster verification | Equal treatment, and the 1.63 artefact; the gap widens from ×2.4 to ×3.0; library dependence; the P-256 residual explained | IMPLEMENTATION, EXPERIMENT, OUR AUDIT |
| 17–19 | IV · The aggregator | One bad signature sinks a batch; BLIND / PREVERIFY / RETAIN; which policy when | OUR FINDING, EXPERIMENT |
| 20–25 | V · Open analysis | Nonce reuse (3 signatures, or 2 for the KGC); **Demo 2**; hedged nonces; the replay claim; the forward-security claim | OUR FINDING, EXPERIMENT |
| 26–30 | VI · Close | Evidence (420 tests, two libraries, audit script); all results; what the paper gets right; scope; three things to remember | |

## Demos

| Slide | Command | Runtime | Point at | Fallback |
|---|---|---|---|---|
| 10 | `make attack`, scroll to TARGET 3 | ~2 s | attacker sees only `pk_TA` and `pk`; `forged sig verifies: True`; repaired scheme `False` | panel on slide 10; larger on B13 |
| 22 | `make nonce` | ~1 s | same `T` three times; recovered `sk` and `c`: True; `KEYS STOLEN`; KGC needs two | panel on slide 22; larger on B13; step 4 is on slide 23 |

Before presenting, run `make test` (420 tests) and both demo commands once on the presentation
machine.

## Rebuilding

```bash
python3 -m venv /tmp/deckenv && /tmp/deckenv/bin/pip install python-pptx pillow
.venv/bin/python presentation/audit/verify_claims_final.py     # asserts every number in the deck
.venv/bin/python presentation/build/make_figures_final.py
.venv/bin/python presentation/build/make_demo_fallback_final.py  # runs both demos, captures output
/tmp/deckenv/bin/python presentation/build/build_final.py        # --no-cues omits presenter cues
/tmp/deckenv/bin/python presentation/build/qc.py Final
/tmp/deckenv/bin/python presentation/build/export_notes.py Final 31
presentation/build/render.sh 110 Final                            # PDF and PNGs in presentation/render_final/
```

The slide modules are `presentation/build/final_a.py` … `final_f.py`. The interim deck still
builds unchanged with `build_deck.py`.

## Claims that need care if asked

- **The key-only forgery is ours, but the principle is textbook.** It is the reason Schnorr
  signatures hash the commitment. Say "not discussed in the paper", not "new to the field": the
  literature has not been searched exhaustively.
- **The R-binding cell of the 2×2 is public-key replacement, not key-only.** In the repaired
  scheme `R_i` belongs to the certificate, so that forgery verifies only if the verifier accepts
  an attacker-chosen `R_i`. Under the real `R_i` it fails 8 / 8. This is the paper's own stated
  reason for hashing `R_i`.
- **Nonce reuse is a standard attack.** Ours is the count for this scheme (3 signatures for an
  outsider, 2 for the KGC) and the KGC case.
- **Forward security:** the paper's ref. [24] is cited by its title only; we have not read it.
- **Not audited:** the paper's EUF-CMA proof. Nothing we found contradicts it.

## Corrections made since the September plan

- The aggregator crossover is stated as "about one bad signature per batch of 200 (0.5%)".
  Individual verification is 1.8× dearer per signature, not 2×.
- The optimisation ratios are quoted as a range over four runs: 2.37–2.46 as specified and
  2.95–3.07 optimised, on P-256.
- The P-256 timing residual is explained by the point encodings inside the hash calls
  (`bench/hashcost.py`), not by interpreter overhead.
- Xiong et al. is not cited as corroboration.
- There is no future-work section. Nonce reuse and the §V-C claims are built and tested; bandwidth
  and MQTT simulation were optional and are not part of the talk.

Reference material: [OPEN_ANALYSIS.md](OPEN_ANALYSIS.md), [KEYONLY_FORGERY.md](KEYONLY_FORGERY.md),
[OPTIMIZATION.md](OPTIMIZATION.md), [AGGREGATOR.md](AGGREGATOR.md).
