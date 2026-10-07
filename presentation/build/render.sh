#!/usr/bin/env bash
# Render the deck to PDF and per-slide PNGs for inspection.
#   presentation/build/render.sh [dpi]
set -euo pipefail
cd "$(dirname "$0")/.."
DPI="${1:-70}"
rm -rf render && mkdir -p render
soffice --headless --convert-to pdf --outdir render CBAS_Interim_Presentation.pptx >/dev/null 2>&1
pdftoppm -r "$DPI" -png render/CBAS_Interim_Presentation.pdf render/s
ls render | wc -l
