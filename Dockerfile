FROM python:3.11.15-slim-bookworm

WORKDIR /app

# Container deployments fail closed unless an operator supplies JWT settings.
ENV SENTINEL_ENV=production

COPY requirements.lock ./
# The Python image supplies the runtime SSL libraries used by Python's ssl
# module. The openssl CLI is only needed by the local TLS test fixture, not by
# the ASGI application, so it is intentionally absent from the runtime image.
RUN python -m pip install --no-cache-dir -r requirements.lock

COPY app ./app
COPY tests ./tests
COPY pyproject.toml ./pyproject.toml
RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /data \
    && chown -R sentinel:sentinel /app /data

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.getenv('PORT', '8000')}/readyz\", timeout=2)"

CMD ["sh", "-c", "exec python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
