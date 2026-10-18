# SENTINEL frontend

The SENTINEL frontend is a dark-first React + TypeScript + Vite dashboard for
the existing FastAPI scan contract. It is intentionally limited to:

- `POST /scans`
- `GET /scans/{scan_id}`
- `POST /scans/{scan_id}/cancel`

When the API returns the optional v0.2 `intelligence` property on
`GET /scans/{scan_id}`, the dashboard exposes it in the **Intelligence** view
and from the scan detail page. v0.1 responses that omit the property remain
valid and show an explicit unavailable state. No intelligence request or local
fallback data is created by the frontend.

## Optional v0.2 intelligence contract

The optional `intelligence` property on `ScanStatusResponse` is published by
the backend and documented in `src/types.ts`. It contains the initial/final
URLs, profile status, bounded summary counts, generic safe observations, and
discovered resources/forms. Each observation/resource includes observed versus
inferred provenance, confidence, status, and minimal response metadata. Older
v0.1 responses may omit the property and remain valid.

The frontend does not manufacture collection sections or enrichment values. MX,
NS, TXT, ASN/provider, and TLS-certificate enrichment is shown as unavailable
by the backend when no safe configured source exists.
The view renders API strings as ordinary React text, so untrusted values are
escaped and never interpreted as markup.

## Optional v0.3 assessment contract

When `GET /scans/{scan_id}` returns `assessment`, the **Assessment** view shows
the API-reported profile, enabled modules, module states, coverage counts,
skipped/unavailable explanations, and assessment findings. Findings can be
searched, filtered, and grouped by severity, verification state, module, or
OWASP category. Evidence is rendered as selected metadata only; the frontend
does not request bodies, add findings, or infer OWASP coverage. Missing
assessment data remains a valid older v0.1/v0.2 response and shows an explicit
empty state.

The interface does not invent scan history or findings. Until a scan is created,
the dashboard shows empty states. A scan must include the explicit authorization
confirmation required by the API. Live detail polling runs every 2.5 seconds,
stops on `completed`, `failed`, or `cancelled`, and is aborted when the view
unmounts.

## Prerequisites

- Node.js `22.23.3` (pinned in `.nvmrc`)
- npm with the checked-in `package-lock.json`
- The SENTINEL FastAPI service running locally or at a configured origin

## Install

From this directory:

```bash
npm ci
```

The optional API origin is configured with `VITE_API_BASE_URL`. It defaults to
the browser's same origin. During Vite development, `/scans` is proxied to
`http://127.0.0.1:8000` by default, avoiding a broad CORS policy:

```bash
cp .env.example .env.local
# Edit VITE_API_BASE_URL only when the API is on another origin.
# Set VITE_DEV_API_TARGET when the local backend uses another port.
```

## Run locally

```bash
npm run dev
```

Open the Vite URL printed in the terminal. For a local API on another port,
set `VITE_DEV_API_TARGET` before `npm run dev`. Use `VITE_API_BASE_URL` only
for a separately deployed API that is already configured to allow the frontend
origin.

## Checks

```bash
npm run typecheck
npm test
npm run build
```

`npm test` runs the offline Vitest suite. The tests cover lifecycle terminal
states, progress boundaries, and display/severity normalization.

## Full-stack Docker demo

From the repository root, start the unchanged FastAPI backend and the static
frontend together:

```bash
docker compose up --build
```

Open `http://127.0.0.1:8080`. The frontend container proxies `/scans` to the
backend service, so no permissive CORS policy is needed. Stop it with:

```bash
docker compose down
```

## Deploy the frontend image alone

Build and serve the static production bundle with the included multi-stage
Dockerfile:

```bash
docker build -t sentinel-frontend .
docker run --rm -p 8080:80 sentinel-frontend
```

`VITE_API_BASE_URL` is a Vite build-time value. To point a standalone production
bundle at another API origin, provide it during the build:

```bash
docker build --build-arg VITE_API_BASE_URL=https://api.example.test -t sentinel-frontend .
```

The frontend image's default `/scans` proxy expects a Compose service named
`backend`; use the Compose workflow above for the reproducible full-stack demo.
