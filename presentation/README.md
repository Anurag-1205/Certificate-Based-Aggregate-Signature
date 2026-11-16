# Final presentation

| File | What it is |
|---|---|
| `CBAS_Final_Presentation.pptx` / `.pdf` | The slides: 30 main slides (about 18 minutes), a Thank You slide, and backup slides B1–B16. Two live demos: `make attack` (slide 11) and `make nonce` (slide 22), each with its captured output on the slide as a fallback. |
| `demo_fallback_final/` | Captured, unedited output of `make attack` (Target 3), the 2×2 ablation tests and `make nonce`. |
| `figures/final_optimisation.png` | The optimisation chart (slide 15). |
| `data/claims_final.json` | Every number in the deck. |
| `data/claims.json` | The interim presentation's numbers, which the final audit re-checks. |
| `audit/verify_claims_final.py` | Recomputes every number in the deck from the code and the recorded benchmarks, asserts each one, and writes `data/claims_final.json`. |

## Re-checking the numbers

```bash
.venv/bin/python presentation/audit/verify_claims_final.py
```

The script stops at the first claim that does not hold. Timing values come from the recorded runs in `bench/results/`. Rerunning the benchmarks (`make bench`) gives new timings, but the same ratios.
