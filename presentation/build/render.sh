#!/usr/bin/env bash
# Render the deck to PDF and per-slide PNGs for inspection.
#   presentation/build/render.sh [dpi] [deck]     deck: Interim (default) or Final
set -euo pipefail
cd "$(dirname "$0")/.."
DPI="${1:-70}"
DECK="CBAS_${2:-Interim}_Presentation"
OUT=render; [ "${2:-Interim}" = Interim ] || OUT="render_${2,,}"
rm -rf "$OUT" && mkdir -p "$OUT"
soffice --headless --convert-to pdf --outdir "$OUT" "$DECK.pptx" >/dev/null 2>&1
pdftoppm -r "$DPI" -png "$OUT/$DECK.pdf" "$OUT/s"
ls "$OUT" | wc -l
