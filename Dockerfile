FROM python:3.11.15-slim-bookworm

WORKDIR /app

COPY requirements.lock ./
# The Python image supplies the runtime SSL libraries used by Python's ssl
# module. The openssl CLI is only needed by the local TLS test fixture, not by
# the ASGI application, so it is intentionally absent from the runtime image.
RUN python -m pip install --no-cache-dir -r requirements.lock

COPY app ./app
COPY tests ./tests
COPY pyproject.toml ./pyproject.toml

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=2)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
