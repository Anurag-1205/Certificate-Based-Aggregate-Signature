PY := .venv/bin/python

.PHONY: help selftest test clean

help:
	@echo "make selftest  - backend algebraic self-test (no pytest needed)"
	@echo "make test      - full pytest suite"
	@echo "make clean     - remove caches"

selftest:
	$(PY) -m cbas.backend.selftest

test:
	$(PY) -m pytest

clean:
	rm -rf .pytest_cache .hypothesis **/__pycache__ src/**/__pycache__
