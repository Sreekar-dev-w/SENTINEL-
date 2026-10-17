# SENTINEL security architecture — Stages 1 and 2

## Boundary

Stage 1 has no network client, crawler, API route, or target-site interaction.
Stage 2 adds one bounded GET request boundary but still has no crawler, API
route, exploitation behavior, or public-site scanning. Network behavior is
available only through explicit client calls and controlled tests.

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

`BoundedHTTPClient` resolves a hostname immediately before each request. It
then builds the transport URL with the selected validated IP literal. This is
the connection-time enforcement boundary: HTTPX is not given the hostname and
therefore cannot independently resolve it to a different address during the
connection.

The logical hostname is retained in the `Host` header. For HTTPS, the request
also carries the original hostname as the HTTPX/httpcore SNI extension. The
default HTTPX certificate verification remains enabled, so connecting to an IP
does not weaken hostname or certificate validation. Environment proxies are
disabled for this controlled boundary so the request cannot be silently routed
through an unrelated proxy.

## Redirect and request limits

Automatic redirects are disabled. Each `Location` value is resolved against
the current URL, normalized, and checked against the initial canonical origin
(scheme, hostname, and effective port). A redirect is followed only when it is
same-origin, resolves to a safe destination, has not already been visited, and
does not exceed the configured redirect limit.

Each response is streamed into a bounded buffer and rejected when it exceeds
`maximum_response_bytes`. HTTPX phase timeouts are configured from
`request_timeout_seconds`, and the client enforces a per-host request budget
across a redirect chain and across requests made by the same client instance.

## Later-phase requirements

The pure policy modules are not sufficient by themselves for network safety.
Future crawler/API layers must preserve the same connection boundary and
revalidate:

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
