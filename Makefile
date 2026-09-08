PY := .venv/bin/python

.PHONY: help selftest test verify clean

help:
	@echo "make selftest  - backend algebraic self-test (no pytest needed)"
	@echo "make test      - full pytest suite"
	@echo "make verify    - selftest + tests + end-to-end demo"
	@echo "make clean     - remove caches"

selftest:
	$(PY) -m cbas.backend.selftest

test:
	$(PY) -m pytest

verify: selftest test
	@echo
	@$(PY) -m cbas.demo

clean:
	rm -rf .pytest_cache .hypothesis **/__pycache__ src/**/__pycache__
