# SENTINEL PenTest

SENTINEL is an authorized, non-destructive web vulnerability assessment tool.
It is being built incrementally. Phase 1 contains only the pure security
foundation: target URL normalization and IPv4/IPv6 destination policy.

## Authorized use

Only assess websites that you own or have explicit permission to test. Phase 1
does not make network requests and does not scan any target.

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

## Phase 1 completion criteria

- Accept and normalize valid HTTP and HTTPS URLs.
- Reject malformed URLs, unsupported schemes, embedded credentials, control
  characters, and ambiguous backslash forms.
- Canonicalize origins with correct default and explicit ports.
- Reject loopback, private, link-local, multicast, reserved, unspecified,
  non-global, IPv4-mapped unsafe, and cloud-metadata IP destinations.
- Cover IPv4 and IPv6 behavior with local unit tests.
- Keep all checks pure and network-free until the next approved phase.

The security design is documented in
[`docs/security-architecture.md`](docs/security-architecture.md).
