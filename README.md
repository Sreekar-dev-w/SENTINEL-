# SENTINEL PenTest

SENTINEL is an authorized, non-destructive web vulnerability assessment tool.
It is being built incrementally. Stage 1 contains the pure security foundation:
target URL normalization and IPv4/IPv6 destination policy. Stage 2 adds a
bounded, same-origin HTTP request boundary with DNS and connection safeguards.
The v0.1 MVP adds an in-memory scan lifecycle, a small API boundary, one
bounded initial request, and four metadata-only checks.

## Authorized use

Only assess websites that you own or have explicit permission to test. The
project does not scan public websites by default, and no exploitation or
destructive behavior is implemented.

## Prerequisites

- Linux or another platform that provides Python 3.11.
- Python `3.11.2`, pinned in `.python-version`.
- Docker Engine is optional for the container workflow.

## Installation

Create the environment inside the checkout and install the pinned lockfile:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
```

No global Python packages are required. Copy `.env.example` to `.env` only if
you want to keep launcher values in a local, untracked file; v0.1 requires no
credentials or secrets. If you use that file, export it in the shell before
launching:

```bash
cp .env.example .env
set -a; . ./.env; set +a
```

## Run the API

The ASGI entrypoint is `app.main:app`. Start it locally with:

```bash
make run
```

By default the API listens on `http://127.0.0.1:8000`. Override the bind
address and port without editing files:

```bash
SENTINEL_HOST=127.0.0.1 SENTINEL_PORT=8000 make run
```

## API examples

The create request requires an explicit authorization confirmation. Replace the
example target only with a site you are authorized to assess; do not use these
commands against public targets for a demo.

```bash
curl -X POST http://127.0.0.1:8000/scans \
  -H 'content-type: application/json' \
  -d '{"target_url":"https://authorized-target.example/","authorization_confirmed":true}'

curl http://127.0.0.1:8000/scans/<scan-id>

curl -X POST http://127.0.0.1:8000/scans/<scan-id>/cancel
```

`POST /scans` returns `202 Accepted` with a scan ID and normally starts in
`queued`. The worker transitions it to `running`, then to exactly one terminal
state: `completed`, `failed`, or `cancelled`. A completed response contains
safe check results and findings only; it does not include response bodies,
cookies, or authorization headers.

## Test

The canonical offline test command is:

```bash
make test
```

The suite uses injected DNS answers and local/mock transports only. The API
smoke test is also directly runnable when verifying the local fixture flow:

```bash
.venv/bin/pytest -q tests/integration/test_api_smoke.py
```

## Docker

The Dockerfile installs the lockfile and starts the ASGI application:

```bash
docker build -t sentinel-pentest .
docker run --rm -p 8000:8000 sentinel-pentest
```

Then use the API examples above against `http://127.0.0.1:8000`. Docker is
optional; if Docker Engine is unavailable, use the Python installation and
`make run` workflow.

## v0.1 scan MVP

The application factory is `app.api.app.create_app()`. It wires the default
in-memory `ScanManager`; tests and embedding applications can inject their own
manager. The API exposes:

- `POST /scans` — validate an HTTP(S) target and explicit authorization, then
  enqueue a scan.
- `GET /scans/{scan_id}` — read queued, running, completed, failed, or
  cancelled state and safe results.
- `POST /scans/{scan_id}/cancel` — request cancellation.

The initial scan performs one bounded GET through `BoundedHTTPClient`, then
checks HSTS, Content-Security-Policy, `X-Content-Type-Options: nosniff`, and
the requested HTTPS transport scheme. It never stores response bodies or
sensitive headers. A scan-wide monotonic deadline, request-attempt budget,
concurrency limit, and finding cap apply independently of the per-request and
per-host safeguards.

## v0.1 limitations

- One target and one bounded GET per scan; no crawler or page graph.
- In-memory scan state; records disappear when the process exits.
- No frontend, authentication system, scheduler, database, or deployment
  configuration.
- The initial check set is intentionally limited to the four metadata-only
  checks described above.
- The production client rejects unsafe DNS destinations and loopback/private
  addresses; controlled tests use the explicit test transport seam instead.

## Stage 2 request boundary

`app.scanning.http_client.BoundedHTTPClient` is a GET-only, asynchronous request
boundary used by the authorized scan orchestration. It uses manual redirects,
strict same-origin enforcement, DNS/IP policy revalidation, a total request
deadline, response-size limits, and per-host request limits.

Before each request, hostname DNS answers are resolved and every IPv4/IPv6
address is validated. The client then sends the connection to a validated IP
literal, rather than passing the hostname back to the HTTP client's resolver.
The original logical hostname is retained in the `Host` header and HTTPS SNI,
so certificate and hostname verification remain enabled.

Each top-level `get()` owns and closes its HTTPX async client and connection pool.
Connections may be reused within that request's same-origin redirect chain, but
separate logical origins cannot share a TLS connection keyed only by a common
validated IP address.

The scanner deadline uses the event loop's monotonic clock and covers DNS
waiting, connection establishment, response headers, response streaming, and
every redirect hop. HTTPX connect/read/write/pool timeouts remain per-operation
safeguards inside that total deadline.

The system resolver uses `asyncio.to_thread(socket.getaddrinfo, ...)`. Cancelling
the await stops SENTINEL from waiting for the result, but cannot forcibly stop
an already-running `getaddrinfo()` thread. If cancellation is suppressed by
caller code, `asyncio.timeout_at` also cannot force immediate termination.

The per-host request budget reserves one attempt before DNS resolution for each
logical hostname. DNS failures, transport failures, timeouts, cancellations,
and redirect responses consume their reservations; redirect follow-ups require
new reservations. Reservation uses a short `threading.Lock` critical section
only around the counter check-and-increment, with no network or async work
inside the lock.

The tests use injected DNS answers and `httpx.MockTransport` fixtures. They do
not contact public websites. Mock transports are available only through the
explicit `BoundedHTTPClient.for_testing(...)` seam; the production constructor
does not accept a custom HTTPX transport.

## Phase 1 completion criteria

- Accept and normalize valid HTTP and HTTPS URLs.
- Reject malformed URLs, unsupported schemes, embedded credentials, control
  characters, and ambiguous backslash forms.
- Canonicalize origins with correct default and explicit ports.
- Reject loopback, private, link-local, multicast, reserved, unspecified,
  non-global, IPv4-mapped unsafe, and cloud-metadata IP destinations.
- Cover IPv4 and IPv6 behavior with local unit tests.
- Keep all checks pure and network-free until the next approved phase.

## Stage 2 completion criteria

- Resolve A and AAAA answers through an injectable boundary and reject every
  unsafe, invalid, or empty result.
- Revalidate DNS/IP policy before each connection attempt and connect only to a
  validated IP literal, preventing hostname re-resolution from bypassing the
  policy.
- Preserve the original hostname for the `Host` header and HTTPS SNI while
  keeping certificate verification enabled.
- Disable automatic redirects and manually enforce strict same-origin scope,
  redirect limits, and loop detection.
- Enforce request timeouts, response-size limits, and per-host request budgets.
- Cover unsafe DNS, changing answers, private and metadata destinations,
  redirect escapes and loops, timeouts, response limits, and request limits
  with controlled local fixtures.
- Verify deadline, cancellation, response cleanup, and the resolver-thread
  limitation with deterministic async fixtures.
- Reserve per-host request budgets atomically under concurrent task races and
  charge failed, cancelled, and redirected attempts.

The security design is documented in
[`docs/security-architecture.md`](docs/security-architecture.md).
