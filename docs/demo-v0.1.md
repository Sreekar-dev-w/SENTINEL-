# SENTINEL v0.1/v0.3 controlled demonstration

This walkthrough demonstrates the API lifecycle and safe reporting without
contacting a public target. The demo injects a fixed DNS answer and an
`httpx.MockTransport`, so it is deterministic and safe to run for a buildathon
review.

## Prepare a clean checkout

From the repository root:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
```

The repository pins Python `3.11.15` in `.python-version`. Docker is an
alternative for launching the ASGI application, but the controlled walkthrough
below is intentionally an in-process demo so its transport cannot reach a
network.

## Run the demonstration

```bash
.venv/bin/python -m examples.demo_v0_1
```

The script performs three API actions:

1. Submits `https://controlled.fixture/` with explicit authorization and
   receives `202 Accepted` plus a scan ID.
2. Polls `GET /scans/{scan_id}` until the scan is `completed`, then prints the
   four legacy check results, remediation text, v0.3 assessment coverage, and
   the single controlled HTTP request.
3. Submits `not-a-url` and receives `422`; the manager is not called and no
   transport request is made.

The response intentionally produces three low-severity metadata findings by
returning a response without HSTS, CSP, or `X-Content-Type-Options: nosniff`.
The fourth HTTPS transport check passes. The fixture includes a body and a
`Set-Cookie` header to make the evidence boundary visible; neither is stored.

Representative output is:

```text
SENTINEL v0.1/v0.3 controlled API demonstration
No public target, DNS lookup, or network socket is used.

1) Submit an authorized scan (POST /scans) -> HTTP 202
{
  "id": "<scan-id>",
  "status": "queued"
}
2) Retrieve the completed result (GET /scans/{scan_id}) -> HTTP 200
   lifecycle: queued -> completed
   checks: 4/4
   findings: 3
   - hsts-missing-or-invalid: Strict-Transport-Security is missing or invalid
     remediation: Return a Strict-Transport-Security header with a positive max-age over HTTPS.
   - csp-missing: Content-Security-Policy is missing
     remediation: Define a restrictive Content-Security-Policy appropriate for the application.
   - x-content-type-options-nosniff-missing: X-Content-Type-Options nosniff is missing
     remediation: Return X-Content-Type-Options: nosniff.
   assessment: partial (9 modules; 6 applicable)
   assessment findings: 6 total, 3 confirmed, 3 potential
   assessment skipped/unavailable: 1/2
   controlled HTTP requests: 1
   response body and Set-Cookie were not stored in the result

3) Reject an invalid target before scanning (POST /scans) -> HTTP 422
```

The lifecycle may include `running` between `queued` and `completed` depending
on scheduling; both are expected. The scan state is in memory and disappears
when the process exits.

## Verification

Run the full offline suite after the walkthrough:

```bash
make test
```

The demo uses the same application factory and injected transport seam as the
integration coverage in `tests/integration/test_api_smoke.py`. It does not add
a crawler, database, credentials, exploit payloads, or uncontrolled network
access. The v0.3 assessment uses the same response and safety boundary as the
legacy checks.
