PY := .venv/bin/python

.PHONY: help selftest test attack verify clean

help:
	@echo "make selftest  - backend algebraic self-test (no pytest needed)"
	@echo "make test      - full pytest suite"
	@echo "make verify    - selftest + tests + demo + attack demo"
	@echo "make attack    - side-by-side forgery demonstration"
	@echo "make clean     - remove caches"

selftest:
	$(PY) -m cbas.backend.selftest

test:
	$(PY) -m pytest

attack:
	$(PY) -m cbas.sidebyside

verify: selftest test
	@echo
	@$(PY) -m cbas.demo
	@echo
	@$(PY) -m cbas.sidebyside

clean:
	rm -rf .pytest_cache .hypothesis **/__pycache__ src/**/__pycache__
