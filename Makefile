.PHONY: setup test compileall demo run build

PYTHON ?= .venv/bin/python

setup:
	python3.11 -m venv .venv
	.venv/bin/python -m pip install -r requirements.lock

test:
	$(PYTHON) -m pytest

compileall:
	$(PYTHON) -m compileall -q app examples tests

demo:
	$(PYTHON) -m examples.demo_v0_1

run:
	$(PYTHON) -m uvicorn app.main:app --host "$${SENTINEL_HOST:-127.0.0.1}" --port "$${SENTINEL_PORT:-8000}"

build:
	$(PYTHON) -m compileall -q app examples
