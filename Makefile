PY := .venv/bin/python

.PHONY: help selftest test attack bench bench-repeat optimize dos plots kaggle-kernel verify clean

help:
	@echo "make selftest  - backend algebraic self-test (no pytest needed)"
	@echo "make test      - full pytest suite"
	@echo "make verify    - selftest + tests + demo + attack demo"
	@echo "make attack    - side-by-side forgery demonstration"
	@echo "make bench     - timing sweep and analysis, both backends"
	@echo "make bench-repeat - repeated sweeps with spread"
	@echo "make optimize  - optimised verification, both schemes"
	@echo "make dos       - aggregator policy under faults"
	@echo "make plots     - render figures from the last bench run"
	@echo "make kaggle-kernel - build the self-contained Kaggle script"
	@echo "make clean     - remove caches"

selftest:
	$(PY) -m cbas.backend.selftest

test:
	$(PY) -m pytest

attack:
	$(PY) -m cbas.sidebyside

bench:
	$(PY) -m bench.report --backend ristretto255
	$(PY) -m bench.report --backend p256

bench-repeat:
	$(PY) -m bench.repeat --repeats 3

dos:
	$(PY) -m bench.dos --backend p256

optimize:
	$(PY) -m bench.optimization --backend p256
	$(PY) -m bench.optimization --backend ristretto255

plots:
	$(PY) -m bench.plots --backend ristretto255
	$(PY) -m bench.plots --backend p256

kaggle-kernel:
	$(PY) -m bench.kaggle.build_kernel

verify: selftest test
	@echo
	@$(PY) -m cbas.demo
	@echo
	@$(PY) -m cbas.sidebyside

clean:
	rm -rf .pytest_cache .hypothesis **/__pycache__ src/**/__pycache__
