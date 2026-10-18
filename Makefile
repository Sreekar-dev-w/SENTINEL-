.PHONY: setup test test-frontend verify compileall demo run build

PYTHON ?= .venv/bin/python
PYTHON_BOOTSTRAP ?= python3.11

setup:
	$(PYTHON_BOOTSTRAP) -c 'import sys; expected=(3,11,15); actual=sys.version_info[:3]; raise SystemExit(f"Python {expected[0]}.{expected[1]}.{expected[2]} is required; found {actual[0]}.{actual[1]}.{actual[2]}") if actual != expected else None'
	$(PYTHON_BOOTSTRAP) -m venv .venv
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

test-frontend:
	npm --prefix frontend test -- --run

verify: test test-frontend compileall demo build
	cd frontend && npm run typecheck && npm run build
