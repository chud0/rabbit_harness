SHELL := /bin/sh
CURRENT_DIR = $(shell pwd)

format:
	@black -l 120 -t py37 -S ./harness

test:
	@export PYTHONPATH=harness; python3 -m unittest discover -s tests -p tests.py
	@pycodestyle --max-line-length=120 --ignore=E203  --exclude settings --first harness

coverage:
	@mkdir -p local
	@export PYTHONPATH=harness; coverage run --rcfile .coveragerc -m unittest discover -s tests -p tests.py
	@coverage html --skip-covered --rcfile .coveragerc
	@coverage report --skip-covered --rcfile .coveragerc
	@echo
	@echo "Coverage:" "file://"$(CURRENT_DIR)"/local/htmlcov/index.html"