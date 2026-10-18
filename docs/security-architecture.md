# SENTINEL security architecture — Stages 1, 2, v0.1, and v0.2

## Boundary

Stage 1 has no network client, crawler, API route, or target-site interaction.
Stage 2 adds one bounded GET request boundary. The v0.1 MVP adds an API route
and in-memory lifecycle around one such request. v0.2 adds a bounded,
same-origin intelligence pass over the initial response and selected linked
resources; it still has no exploitation behavior or public-site scanning.
Network behavior is available only after HTTP(S) and authorization validation,
through the bounded client, and in controlled tests.

## URL policy

`app.security.url_validation.normalize_target_url` accepts only `http` and
`https` URLs. It rejects empty or malformed URLs, unsupported schemes,
embedded username/password credentials, control characters, whitespace, and
backslashes. It removes fragments, supplies `/` for an empty path, normalizes
hostnames through IDNA or IP canonicalization, and records the effective port.

The returned `NormalizedURL.origin` is the future input to same-origin scope
enforcement. Default ports are represented canonically: `http` uses 80 and
`https` uses 443.

## Destination policy

`app.security.ip_policy` classifies IPv4 and IPv6 destinations. It rejects:

- Loopback addresses
- Private addresses
- Link-local addresses
- Multicast addresses
- Reserved addresses
- Unspecified addresses
- Non-global addresses such as documentation ranges
- IPv4-mapped IPv6 representations of unsafe IPv4 addresses
- Known cloud metadata addresses
- IPv6 zone identifiers

The policy rejects an empty resolution result and requires every address in a
resolution set to pass. This is important for later DNS validation: a caller
must not treat one safe result as authorization to ignore another unsafe
result.

## DNS and connection enforcement

`app.security.dns` defines an injectable asynchronous resolver boundary. The
system implementation uses `getaddrinfo` with `AF_UNSPEC` and `SOCK_STREAM` so
both A and AAAA results are considered. A resolution is accepted only when it
is non-empty and every result passes `validate_ip_addresses`; one unsafe answer
rejects the complete set.

`BoundedHTTPClient` is asynchronous and resolves a hostname immediately before
each request. It then builds the transport URL with the selected validated IP
literal. This is the connection-time enforcement boundary: HTTPX is not given
the hostname and therefore cannot independently resolve it to a different
address during the connection.

The logical hostname is retained in the `Host` header. For HTTPS, the request
also carries the original hostname as the HTTPX/httpcore SNI extension. The
default HTTPX certificate verification remains enabled, so connecting to an IP
does not weaken hostname or certificate validation. Environment proxies are
disabled for this controlled boundary so the request cannot be silently routed
through an unrelated proxy.

The HTTPX client and connection pool are scoped to one top-level request. A
same-origin redirect chain can reuse its connection, but a later top-level
request gets a new pool. This prevents the pool's IP-based origin key from
reusing a TLS connection authenticated for a different logical hostname that
happens to resolve to the same IP. A separately injected custom transport is
not accepted by the production constructor. Tests use the explicit
`BoundedHTTPClient.for_testing(...)` seam with a fresh transport factory; that
seam is not a production security boundary and is never used by normal
construction.

## Redirect and request limits

Automatic redirects are disabled. Each `Location` value is resolved against
the current URL, normalized, and checked against the initial canonical origin
(scheme, hostname, and effective port). A redirect is followed only when it is
same-origin, resolves to a safe destination, has not already been visited, and
does not exceed the configured redirect limit.

Each response is streamed into a bounded buffer and rejected when it exceeds
`maximum_response_bytes`. A monotonic deadline starts at the beginning of each
top-level request and covers DNS waiting, connection establishment, response
headers, response streaming, and all redirect hops. HTTPX connect/read/write/
pool timeouts are configured from the remaining deadline at each request; they
are per-operation safeguards, not the total budget. The client also enforces a
per-host request budget across a redirect chain and across requests made by the
same client instance.

The complete async operation is wrapped in `asyncio.timeout_at`. On timeout or
task cancellation, response streams are closed in `finally` blocks and the
per-request `AsyncClient` context closes its transport pool. `CancelledError`
is not swallowed. The system resolver still uses `asyncio.to_thread`; cancelling
its await does not terminate an already-running `getaddrinfo()` call. Likewise,
`asyncio.timeout_at` cannot forcibly terminate work if caller code suppresses
cancellation, so these are cooperative guarantees rather than thread/process
termination guarantees.

Request budgets count attempted logical HTTP requests. A reservation is made
before DNS resolution and before any transport attempt, so DNS errors,
transport failures, timeouts, and cancellation consume budget and cannot be
retried indefinitely without accounting. Each redirect follow-up reserves a
new attempt. URL validation and cross-origin redirect rejection happen before
their corresponding follow-up reservation because no request is attempted.

The shared per-host counter is guarded by a `threading.Lock` around only the
check-and-increment operation. No lock is held across DNS, connection, response
streaming, redirects, or any `await`, so concurrent tasks and callers using
separate threads cannot exceed the configured limit or deadlock on I/O.

## v0.1 scan lifecycle and reporting

`app.api.models.CreateScanRequest` requires an HTTP(S) target and the literal
authorization confirmation `true`. It normalizes the target before the manager
is called. `ScanManager` creates a queued record, transitions it atomically to
running, and reaches exactly one terminal state: completed, failed, or
cancelled. Cancellation races are resolved by the store lock; a terminal scan
cannot be overwritten by a late worker transition.

Each scan owns one `ScanBudget` and one bounded HTTP client. The budget reserves
an attempt before the network call and retains that reservation on failure or
cancellation. The scan deadline covers budget waiting and the bounded client
operation. The initial check layer is pure after the response arrives and
stores only selected response metadata. Findings are flattened for the API,
while cookies, authorization headers, and response bodies are excluded.

The v0.1 baseline is intentionally one-request and one-target. Crawl depth,
page count, additional checks, persistence, authentication, and scheduling are
not part of that baseline; bounded v0.2 intelligence is described below.

## v0.2 intelligence boundary

`WebsiteIntelligenceEngine` uses the initial response, the same
`BoundedHTTPClient`, and the same `ScanBudget` owned by the scan. The engine
records target/final URLs, redirect metadata, page title/content type, selected
safe technology and edge headers, validated A/AAAA answers, same-origin
resources, and forms. It does not execute JavaScript, submit forms, follow
cross-origin resources, or perform unconstrained crawling.

The default collection limits are a 30-second scan deadline, 2 MB response
limit, depth 2, 50 pages, 50 requests per scan, and 50 requests per host. Each
candidate is normalized and deduplicated before a request. Cross-origin and
over-limit candidates are retained only as limited resource records. Forms are
retained as metadata and never requested, including GET actions that might have
side effects. `robots.txt` and sitemap references are treated as bounded
same-origin candidates rather than as permission to leave the target origin.

The profile is safe metadata, not a response archive. `MinimalEvidence` permits
only a small header allowlist; cookies, authorization headers, response bodies,
and complete header maps cannot enter the profile. URL query values are
redacted. Unsupported MX/NS/TXT, ASN/provider, and TLS-certificate enrichment
is represented explicitly as unavailable rather than guessed or delegated to a
new external service. Intelligence exceptions are isolated from the v0.1
checks and produce an error profile instead of silently changing scan status.

## v0.3 assessment boundary

`app.assessment` contains the immutable registry, restricted execution context,
passive module implementations, and coverage accounting. A module receives a
metadata-only `ResponseSnapshot` and the Stage 1 `WebsiteProfile`; it does not
receive a response body, raw cookie values, a resolver, a transport, or an
unrestricted HTTP client. Future same-origin GETs, if explicitly enabled for a
low-impact module, go through `AssessmentContext.get_same_origin`, which
revalidates origin/port scope and charges the shared scan budget.

The default v0.3 profile runs security-header reuse, cookie-attribute, CORS,
redirect, information-exposure, and API-inventory observations. It also
reports TLS metadata, authenticated authorization, and external vulnerability
intelligence as unavailable/skipped when their capabilities or prerequisites
are absent. It never treats a 401/403 response, a weak technology fingerprint,
an unavailable lookup, or a failed request as proof of a vulnerability.

Findings carry explicit verification state, test ID/version, exact reference
keys, OWASP category/identifier, timestamp, safe evidence, and remediation.
Coverage separately counts applicable, passed, confirmed, potential,
informational, skipped, unavailable, and execution-failure results. The
registry records these verified reference versions and identifiers:

- WSTG 4.2: `WSTG-CONF-07`, `WSTG-CONF-12`, `WSTG-CONF-14`, `WSTG-SESS-02`,
  `WSTG-CLNT-07`, `WSTG-INFO-02`, and `WSTG-APIT-01`.
- OWASP Top 10:2025: `A02:2025`, `A03:2025`, `A04:2025`, and `A07:2025`.
- ASVS 5.0.0: version-qualified requirements including
  `v5.0.0-3.3.1`, `v5.0.0-3.3.2`, `v5.0.0-3.3.4`, `v5.0.0-3.4.2`,
  `v5.0.0-3.4.3`, `v5.0.0-3.4.4`, `v5.0.0-8.1.1`, `v5.0.0-12.2.1`,
  and `v5.0.0-12.2.2`.
- API Security Top 10:2023: `API2:2023`, `API8:2023`, and `API9:2023`.

This is tracked module coverage, not comprehensive OWASP coverage and not a
complete penetration test.

## Later-phase requirements

The pure policy modules are not sufficient by themselves for network safety.
Future broader crawler and persistence layers must preserve the same connection
boundary and revalidate:

1. URL scheme, hostname, credentials, and canonical origin.
2. All current A and AAAA DNS results.
3. Private, metadata, loopback, link-local, multicast, reserved, and other
   non-global ranges.
4. Same-origin scope.
5. Timeout, response-size, crawl-depth, concurrency, and per-host budgets.

Automatic redirect following remains disabled so every redirect passes through
these checks before the next request.

## Verification

The unit suite covers valid URL normalization, malformed inputs, unsupported
schemes, embedded credentials, IPv4 and IPv6 unsafe ranges, metadata ranges,
IPv4-mapped IPv6 values, invalid addresses, empty resolution sets, and mixed
safe/unsafe resolution results. Stage 2 integration fixtures cover unsafe DNS
answers, changing answers, redirect scope and loops, timeout propagation,
response-size limits, request limits, logical Host preservation, and HTTPS SNI
preservation without contacting public websites.
