# Build the project report.   make        -> main.pdf, copied to ../CBAS_Final_Report.pdf
#                               make clean  -> remove LaTeX by-products
TEX := pdflatex -interaction=nonstopmode -halt-on-error

main.pdf: main.tex refs.bib sections/*.tex
	$(TEX) main >/dev/null
	bibtex main >/dev/null
	$(TEX) main >/dev/null
	$(TEX) main | grep -E "Warning|Error|Output written" || true
	cp main.pdf ../CBAS_Final_Report.pdf

clean:
	rm -f main.aux main.bbl main.blg main.log main.out main.toc main.lof main.lot

.PHONY: clean
