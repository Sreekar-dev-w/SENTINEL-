FROM python:3.11.2-slim

WORKDIR /app

COPY requirements.lock ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir -r requirements.lock

COPY app ./app
COPY tests ./tests
COPY pyproject.toml ./pyproject.toml

CMD ["python", "-m", "pytest"]
