# SENTINEL PenTest

SENTINEL is an authorized, non-destructive web vulnerability assessment tool.
It is being built incrementally. Stage 1 contains the pure security foundation:
target URL normalization and IPv4/IPv6 destination policy. Stage 2 adds a
bounded, same-origin HTTP request boundary with DNS and connection safeguards.

## Authorized use

Only assess websites that you own or have explicit permission to test. The
project does not scan public websites by default, and no exploitation or
destructive behavior is implemented.

## Setup

Python 3.11.2 is pinned in `.python-version`.

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
```

## Test

```bash
make test
```

## Stage 2 request boundary

`app.scanning.http_client.BoundedHTTPClient` is a GET-only, synchronous request
boundary for later authorized scan orchestration. It uses manual redirects,
strict same-origin enforcement, DNS/IP policy revalidation, bounded timeouts,
response-size limits, and per-host request limits.

Before each request, hostname DNS answers are resolved and every IPv4/IPv6
address is validated. The client then sends the connection to a validated IP
literal, rather than passing the hostname back to the HTTP client's resolver.
The original logical hostname is retained in the `Host` header and HTTPS SNI,
so certificate and hostname verification remain enabled.

Each top-level `get()` owns and closes its HTTPX client and connection pool.
Connections may be reused within that request's same-origin redirect chain, but
separate logical origins cannot share a TLS connection keyed only by a common
validated IP address.

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

The security design is documented in
[`docs/security-architecture.md`](docs/security-architecture.md).
