# SENTINEL security architecture — Phase 1

## Boundary

Phase 1 has no network client, crawler, API route, or target-site interaction.
The implementation only accepts untrusted URL strings and IP strings and
returns validated policy objects or explicit rejection errors.

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

## Later-phase requirements

The pure policy modules are not sufficient by themselves for network safety.
When network access is added, every connection and redirect must revalidate:

1. URL scheme, hostname, credentials, and canonical origin.
2. All current A and AAAA DNS results.
3. Private, metadata, loopback, link-local, multicast, reserved, and other
   non-global ranges.
4. Same-origin scope.
5. Timeout, response-size, crawl-depth, concurrency, and per-host budgets.

Automatic redirect following will remain disabled so every redirect can pass
through these checks before the next request.

## Phase 1 verification

The unit suite covers valid URL normalization, malformed inputs, unsupported
schemes, embedded credentials, IPv4 and IPv6 unsafe ranges, metadata ranges,
IPv4-mapped IPv6 values, invalid addresses, empty resolution sets, and mixed
safe/unsafe resolution results.
