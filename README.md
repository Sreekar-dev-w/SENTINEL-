# SENTINEL PenTest

SENTINEL is an authorized, non-destructive web vulnerability assessment tool.
It is being built incrementally. Stage 1 contains the pure security foundation:
target URL normalization and IPv4/IPv6 destination policy. Stage 2 adds a
bounded, same-origin HTTP request boundary with DNS and connection safeguards.
The v0.1 MVP adds an in-memory scan lifecycle, a small API boundary, one
bounded initial request, and four metadata-only checks. v0.2 adds an optional,
bounded Website Intelligence profile to the same scan result without changing
the v0.1 checks or lifecycle. v0.3 adds a passive assessment registry,
evidence-backed findings, coverage reporting, and a dashboard view; it does not
add exploit or authenticated scanning. v0.4 Stage 3 adds opt-in TLS metadata
and DNS/hosting attribution seams plus a reusable network-assessment policy; it
does not add a general port scanner or generic socket API. v0.5 adds explicit
engagement authorization, profile-bound assessment orchestration,
finding verification/deduplication, and deterministic report export; these
remain in-memory and metadata-only.

## Authorized use

Only assess websites that you own or have explicit permission to test. The
project does not scan public websites by default, and no exploitation or
destructive behavior is implemented.

## Prerequisites

- Linux or another platform that provides Python 3.11.
- Python `3.11.15`, pinned in `.python-version` and matched by the Docker
  base image.
- Docker Engine is optional for the container workflow.

## Installation

Create the environment inside the checkout and install the pinned lockfile:

```bash
make setup
```

`make setup` uses Python `3.11.15` and installs only the checked-in
`requirements.lock`. It needs a package index or a locally configured pip
cache. For an already provisioned checkout, all test, compile, and demo
commands below are offline and do not contact a package index. To provision a
new checkout fully offline, provide a local wheelhouse containing the locked
packages:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --no-index --find-links=/path/to/wheelhouse -r requirements.lock
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

Additional release checks are available without network access:

```bash
make compileall
make demo
make build
```

The suite uses injected DNS answers and local/mock transports only. The API
smoke test is also directly runnable when verifying the local fixture flow:

```bash
.venv/bin/pytest -q tests/integration/test_api_smoke.py
```

## Buildathon demonstration

For a judge-friendly, fully controlled walkthrough that prints the scan ID,
completed findings, remediation text, lifecycle, and invalid-target rejection,
run:

```bash
.venv/bin/python -m examples.demo_v0_1
```

See [`docs/demo-v0.1.md`](docs/demo-v0.1.md) for the expected output and the
fixture boundaries. The demo uses an injected resolver and mock transport; it
does not contact public targets.

## Docker

The Dockerfile installs the lockfile, starts the ASGI application, and marks
the container healthy only when `/readyz` returns successfully:

```bash
docker build -t sentinel-pentest .
docker run --rm -p 127.0.0.1:8000:8000 sentinel-pentest
```

Then use the API examples above against `http://127.0.0.1:8000`. Verify the
service probes directly with:

```bash
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:8000/readyz
```

Docker is optional; if Docker Engine is unavailable, use the Python
installation and `make run` workflow. The Compose demo binds to loopback by
default and waits for the backend readiness check before starting the
frontend:

```bash
cp .env.example .env
docker compose up --build
docker compose ps
docker compose down
```

Set `SENTINEL_BIND_HOST` deliberately in `.env` only when the services should
be reachable beyond loopback. `SENTINEL_BACKEND_PORT` and
`SENTINEL_FRONTEND_PORT` change the host-side ports; container ports remain
8000 and 80. Both services expose Docker health status, and the backend
readiness probe does not initiate a scan or external network request.

## v0.1 scan MVP

The application factory is `app.api.app.create_app()`. It wires the default
in-memory `ScanManager`; tests and embedding applications can inject their own
manager. The API exposes:

- `GET /healthz` — process liveness response that does not touch scan state.
- `GET /readyz` — application readiness response; returns `503` if required
  application services are not wired.
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
per-host safeguards. The optional v0.2 intelligence pass uses the same client
and budget; if it fails, the v0.1 checks still complete and the API reports an
intelligence error state rather than failing the scan.

## v0.2 Website Intelligence

Completed scans may include an optional `intelligence` object. It reports safe,
structured observations for the target/final URL, redirect chain, page metadata,
validated A/AAAA addresses, selected technology and edge indicators, discovered
same-origin resources, and forms. It also reports explicit unavailable states
for MX/NS/TXT, ASN/provider, and TLS-certificate enrichment when no configured
safe source exists.

Collection is deliberately bounded by the existing `ScanLimits`: the default
scan deadline is 30 seconds, the maximum response size is 2 MB, the maximum
same-origin depth is 2, the maximum pages/requests per scan is 50, and the
maximum per-host requests is 50. Cross-origin resources are recorded as
limited/blocked and are never fetched. Forms are recorded but never submitted;
JavaScript is never executed. URLs and query values are normalized/redacted,
and evidence contains only a small allowlist of non-sensitive headers. Response
bodies, cookies, authorization material, and complete header maps are never
returned by the API.

The `intelligence` property is optional so clients that receive a v0.1 response
without it remain compatible. The dashboard's Intelligence view renders
observed, inferred, partial, limited, unavailable, and error states without
inventing values.

## v0.3 passive assessment backend

The v0.3 assessment package is under `app/assessment/`. Its immutable registry
contains passive/low-impact modules for security headers (reusing the existing
HSTS, CSP, and `X-Content-Type-Options` checks), cookie attributes, CORS,
bounded redirect/configuration observations, safe metadata disclosure
indicators, and API inventory observations from the Stage 1 asset map. Each
module emits safe findings or observations with verification, module/test,
reference, and timestamp metadata. Standards are recorded explicitly as WSTG
4.2 (stable), OWASP Top 10:2025, ASVS 5.0.0, and API Security Top 10:2023.

TLS metadata, authenticated authorization, and external vulnerability
intelligence are represented as unavailable or skipped modules when their
required provider/context is absent. Assessment requests, if a future passive
module needs one, must use the existing `BoundedHTTPClient` and `ScanBudget`
through `AssessmentContext`; modules cannot create transports, bypass DNS or
redirect policy, or retain response bodies/cookie values. Assessment output is
available as `assessment` and optional top-level `coverage` fields while the
legacy `checks`, `findings`, and summary remain compatible.

## v0.4 controlled application-security lab

The opt-in `CONTROLLED_APPLICATION_SECURITY_REGISTRY` in
`app.assessment.registry` adds deterministic, in-process modules for a
protected-route expectation, session-cookie flag metadata, two-user
object-level authorization, and one bounded malformed-input/content-type
probe. Construct an approved `LabScope`, declare the lab capabilities and
assessment prerequisites, then pass the synthetic `InProcessAssessmentLab` on
`AssessmentContext`. The lab accepts only synthetic user/role/resource IDs and
returns metadata; it has no HTTP client, credentials, request payloads,
response bodies, or cookie values. An unconfigured lab remains unavailable or
skipped and the v0.3 default registry is unchanged.

Authorization compares explicit expected access with ownership/policy
metadata, so a deliberately configured cross-user access flaw is detected
without treating an HTTP status as proof. Input handling reports validation
failure, safe error handling, and explicitly observed injection separately;
malformed input alone never becomes an injection finding. Results use the
existing verification, evidence, and coverage models and exact WSTG 4.2,
OWASP Top 10:2025, ASVS 5.0.0, and API Security Top 10:2023 references.

## v0.4 Stage 3 infrastructure

Stage 3 infrastructure is opt-in and remains metadata-only:

- `app.security.tls` defines an injected `TLSMetadataProbe` boundary. A probe
  receives only a hostname, a destination address validated immediately before
  connection, and an explicitly permitted port. `TLSProbeResult` can report
  valid, invalid, handshake-failure, hostname-mismatch, unavailable, or error
  states, with safe subject/issuer, validity interval, chain/hostname
  verification, protocol/cipher metadata, confidence, and timestamp when the
  injected probe can establish them. HTTPS alone is never treated as
  certificate validity; normal HTTPX certificate verification remains enabled.
  Raw certificates, private keys, page content, cookies, and credentials are
  not accepted by this interface.
- `app.scanning.intelligence_providers` defines optional dependency-free DNS
  and hosting provider protocols. They may report CNAME, MX, NS, TXT, DNSSEC,
  ASN/network/provider, CDN, reverse-proxy, and WAF observations with explicit
  unavailable/failure state, timestamp, and confidence. Providers receive only
  the hostname and validated addresses. No provider is configured by default.
- `WebsiteIntelligenceEngine` appends injected provider/TLS observations while
  retaining the existing profile shape and the v0.1/v0.2 default output when no
  provider is supplied. DNS attribution failures degrade to an explicit error;
  validated A/AAAA observations remain independent.
- `app.security.network_policy.NetworkAssessmentPolicy` authorizes one
  connection at a time against existing DNS/IP safety rules, explicitly
  approved CIDRs, prohibited destinations, permitted HTTP/TLS ports and service
  types.
  It models request/deadline/global and per-host concurrency/rate limits,
  cancellation-safe leases, cleanup, and safe audit metadata. The policy is a
  connection boundary only: it does not enumerate ports, open generic sockets,
  scan services, submit content, or bypass the existing `BoundedHTTPClient`.

The default HTTP profile still uses `ScanLimits.allowed_ports` `(80, 443)` and
the existing validated-IP connection path. The typed external-tool boundary in
`app.external_tools` is the first approved integration point for a real
scanner. `ZAPAdapter` uses the supported OWASP ZAP JSON API (`core/version`,
bounded `core/accessUrl`, passive-queue status, and `core/alerts`) through an
injected `ExternalToolTransport`. Its result models carry tool identity/version,
availability, execution state, bounded diagnostics, and normalized findings
with source, rule, and provenance. The real `ZAPHTTPTransport` talks to an
already-running service; it does not launch a process or store API keys.

ZAP execution requires an active `EngagementScopePolicy`, and the requested
target and returned alert URLs are checked against that policy. Passive
scanning is the default. Active scanning is only attempted when the caller
sets both `active_scan=True` and `active_testing_authorized=True`, and the
engagement explicitly allows the `zap.active_scan` capability. The deterministic
adapter tests use a fake supported-API transport and do not run ZAP or contact
public targets. Broad service discovery, unrestricted port scanning, and raw
certificate inspection remain outside this boundary.

The optional `NmapAdapter` and `TestSSLAdapter` use the same contract with an
injected, argument-array-only process runner. Nmap accepts only the bounded
`discovery`/`host_discovery` and explicitly authorized `service_detection`
modes, emits XML observations, and never turns discovery into a vulnerability
finding. Testssl.sh accepts JSON or CSV machine output, requires an authorized
HTTPS infrastructure target and capability, and emits protocol observations
plus normalized findings only for failing or vulnerable checks. Both adapters
enforce engagement ports, execution deadlines, output limits, cancellation,
safe process termination, and sanitized unavailable/nonzero/malformed/partial
states. Their deterministic tests use fake process results; no Nmap or
testssl.sh binary is installed or executed by the test suite.

The engagement launch workflow exposes the supported tool identifiers returned by
`GET /external-tools` (`owasp-zap`, `nmap`, and `testssl.sh`). Operators must
select tools explicitly; native checks remain the default. Available adapters can
be selected, while unavailable or unconfigured tools are shown with their
diagnostic and disabled in the UI. A failed availability probe does not block a
native launch, but it also does not imply that any external tool ran. The launch
request sends the selected IDs as `external_tools`; the API normalizes and
deduplicates them, then the engagement policy and adapter capability requirements
remain authoritative. Unknown IDs are rejected by the application allow-list.
Nmap and testssl.sh additionally require the active-testing confirmation in the
launch form. Selected tool state, normalized findings, safe provenance, and
unavailable/partial/cancelled diagnostics are carried through scan status and
both report formats.

## v0.5 engagements, profiles, and reports

The v0.5 scan path accepts an optional server-side `engagement_id` and
`assessment_profile`. Omitting both preserves the legacy passive profile. The
controlled application-security profile additionally requires an active
engagement that allows the profile and its capabilities, plus explicit
`active_testing_authorized: true`; it uses only an injected synthetic lab.
Engagement scope, expiry, exclusions, ports, service types, budgets, and
cancellation are enforced again when queued work starts.

The default application factory wires a secure synthetic lab for this opt-in
profile. Create the engagement first, including the four lab capabilities, then
submit the controlled scan:

```bash
curl -X POST http://127.0.0.1:8000/engagements \
  -H 'content-type: application/json' \
  -d '{"target_domains":["authorized-target.example"],"allowed_assessment_profiles":["controlled-lab"],"allowed_capabilities":["lab.authentication","lab.session-cookie-metadata","lab.authorization","lab.input-validation"],"authorization_reference":"owner-approval"}'

# Use the returned .id as <engagement-id>; do not paste credentials or secrets.
curl -X POST http://127.0.0.1:8000/scans \
  -H 'content-type: application/json' \
  -d '{"target_url":"https://authorized-target.example/","engagement_id":"<engagement-id>","assessment_profile":"controlled-lab","active_testing_authorized":true,"authorization_confirmed":true}'
```

The controlled lab evaluates synthetic authentication, session-cookie metadata,
object-authorization, and bounded input-validation outcomes. It does not send
authenticated requests or exploit payloads; the only target network action is
the existing bounded initial GET.

### Durable single-node state

The default test and library configuration remains in-memory. Set
`SENTINEL_STATE_DB` to an application-owned SQLite path to persist engagement
metadata and scan snapshots. Compose configures `/data/sentinel.sqlite3` on the
named `sentinel-data` volume. Terminal scans, external-tool provenance, reports,
and engagement lifecycle metadata survive a process restart; queued or running
scans are recovered as failed with an explicit restart error rather than being
silently re-executed. SQLite is intended for one application node only. A
multi-worker deployment requires a server database and a durable worker/lease
design, which are not claimed here. Back up the configured database file or
volume using the deployment platform's encrypted backup mechanism; do not store
credentials in it.

### OIDC/JWT ownership boundary

For a trusted deployment, set `SENTINEL_JWT_SECRET` and optionally
`SENTINEL_JWT_ISSUER` and `SENTINEL_JWT_AUDIENCE`. Requests must then carry a
Bearer JWT using `HS256`, with `sub`, `exp`, and optional `tenant`/`org_id` and
`roles` claims. Engagements and scans are stamped with the authenticated subject
and tenant; reads, reports, cancellation, and scan admission reject resources
owned by another subject or tenant as not found. The frontend can send a
deployment-provided token through `VITE_API_TOKEN`; do not commit that value.
The secret must be supplied through a deployment secret manager, not a checked-in
`.env` file. When no secret is configured, the app intentionally stays in
loopback/local-development mode for the existing offline demo and tests; that
mode is not an internet-facing authorization boundary.

Finding records carry an explicit verification state (`confirmed`, `potential`,
`not_verified`, or another documented state). Aggregate assessment and scan
views deduplicate only equivalent findings, preserving distinct checks,
targets, modules, and material descriptions while retaining raw module/check
results for traceability. The pure `transition_finding` seam validates
verification and resolution transitions and appends bounded audit metadata;
resolving a finding never implies that remediation was independently verified.

Terminal scans (`completed`, `failed`, or `cancelled`) can be exported without
writing files:

```bash
curl http://127.0.0.1:8000/scans/<scan-id>/report?format=json
curl http://127.0.0.1:8000/scans/<scan-id>/report?format=markdown
```

Reports are unavailable while a scan is queued or running. JSON uses canonical key and
section ordering; Markdown is stable and human-readable. Both formats include
profile, engagement, summary, coverage, checks, modules, findings, and only
safe evidence. Query values, cookies, response bodies, authorization headers,
and non-allowlisted headers are excluded. Report state follows the in-memory
scan manager and is lost when the process exits.

## v0.6 unified assessment workflow

The existing scan entry point now publishes safe interim assessment snapshots
while a running scan advances through its registered modules. The dashboard can
observe pending, running, completed, skipped, unavailable, and error module
states without receiving findings or raw evidence before the authoritative final
result. The final result retains the same shared budget, cancellation event,
engagement policy, bounded HTTP client, and profile admission checks.

The v0.6 report uses `report_version: "0.6"`, includes an executive summary,
prioritized aggregate findings from both legacy checks and assessment modules,
skipped checks, unmet prerequisites, partial-failure limitations, remediation,
verification state, and sanitized evidence. It still reports only configured
modules and does not claim comprehensive OWASP coverage.

## Web dashboard

The `frontend/` directory contains a React + TypeScript + Vite dashboard for
the existing API. It does not invent scanner results or persistent history. The
dashboard shows the latest scan returned by the API, supports live status
polling and cancellation, and renders safe findings with severity,
check, status, evidence, and remediation filters. Its optional Intelligence
view renders the v0.2 profile when the API includes it.

For local development, start the backend first and then the frontend. Vite
proxies `/scans` to the backend without requiring permissive CORS:

```bash
make run
cd frontend
npm ci
npm run dev
```

Open the Vite URL, normally `http://127.0.0.1:5173`. The frontend runtime is
Node.js `22.23.3`, pinned in `frontend/.nvmrc`. Run frontend checks with:

```bash
npm run typecheck
npm test
npm run build
```

The frontend checks are all offline after `npm ci` has populated the checked-in
lockfile's dependency tree. When the npm cache is already populated, a clean
offline install can be requested with `npm ci --offline`.

For a reproducible full-stack container demo (with loopback host bindings and
backend readiness gating):

```bash
docker compose up --build
```

Then open `http://127.0.0.1:8080`. The frontend container proxies API requests
to the unchanged backend container. Check container health with
`docker compose ps`, then stop it with `docker compose down`.

## v0.1 baseline limitations

- One target and one bounded initial GET per scan; v0.2 intelligence adds only
  the bounded same-origin resource pass described above.
- In-memory state is the default library/test mode. A single-node SQLite snapshot
  mode is available through `SENTINEL_STATE_DB`; it does not provide distributed
  worker recovery or multi-user authorization.
- No authentication or actor-ownership system is currently provided. The
  `authorization_confirmed` field and free-text authorization reference are audit
  metadata, not proof of caller identity. Do not expose the API beyond a trusted
  local boundary until an authentication and ownership policy is deployed.
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
