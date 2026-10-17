.PHONY: test run

test:
	.venv/bin/python -m pytest

run:
	.venv/bin/python -m uvicorn app.main:app --host "$${SENTINEL_HOST:-127.0.0.1}" --port "$${SENTINEL_PORT:-8000}"
