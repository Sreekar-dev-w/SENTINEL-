"""FastAPI application factory for SENTINEL's API contract layer."""

from __future__ import annotations

import ipaddress
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import ScanManager, router
from app.auth import JWTConfig
from app.assessment.lab import build_secure_application_security_lab
from app.external_tools import NmapAdapter, TestSSLAdapter, ZAPAdapter, ZAPHTTPTransport
from app.reporting import ReportExporter


PRODUCTION_FRONTEND_ORIGIN = "https://sentinelpentest.netlify.app"


def _configured_cors_origins() -> list[str]:
    """Return an explicit CORS allow-list without accepting a wildcard.

    The deployed Netlify frontend is the safe default production origin. Local
    or separately hosted development origins remain configurable through
    ``SENTINEL_CORS_ORIGINS``.
    """

    raw = os.getenv("SENTINEL_CORS_ORIGINS", PRODUCTION_FRONTEND_ORIGIN)
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    if "*" in origins:
        raise ValueError("SENTINEL_CORS_ORIGINS must contain explicit origins")
    return list(dict.fromkeys(origins))


def _is_loopback_bind(host: str) -> bool:
    normalized = host.strip().casefold()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def create_app(scan_manager: ScanManager | None = None) -> FastAPI:
    """Build an API application with an application-owned manager.

    Passing ``scan_manager`` is the normal integration seam.  Leaving it out
    is useful for importing the contract or mounting the router before the
    runner wires its manager; requests then receive a clear 503 response.
    """

    if scan_manager is None:
        from app.scanning.runner import ScanManager

        # Only the application-owned default manager receives the safe
        # synthetic lab. Explicitly injected managers retain their seam.
        # External adapters are configured but never executed unless a request
        # selects them and an engagement authorizes the required capability.
        zap_transport = ZAPHTTPTransport(
            os.getenv("SENTINEL_ZAP_URL", "http://127.0.0.1:8080"),
            api_key=os.getenv("SENTINEL_ZAP_API_KEY") or None,
        )
        scan_manager = ScanManager(
            assessment_lab_factory=build_secure_application_security_lab,
            state_db_path=os.getenv("SENTINEL_STATE_DB") or None,
            external_adapters={
                "owasp-zap": ZAPAdapter(zap_transport),
                "nmap": NmapAdapter(
                    executable=os.getenv("SENTINEL_NMAP_EXECUTABLE", "nmap")
                ),
                "testssl.sh": TestSSLAdapter(
                    executable=os.getenv("SENTINEL_TESTSSL_EXECUTABLE", "testssl.sh")
                ),
            },
        )

    app = FastAPI(title="SENTINEL API", version="0.1.0")
    cors_origins = _configured_cors_origins()
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Accept", "Authorization", "Content-Type"],
        )
    app.state.scan_manager = scan_manager
    app.state.engagement_store = getattr(scan_manager, "engagement_store", None)
    app.state.report_exporter = ReportExporter()
    jwt_secret = os.getenv("SENTINEL_JWT_SECRET") or None
    environment = os.getenv("SENTINEL_ENV", "development").strip().casefold()
    production_like = environment in {"production", "prod", "staging"}
    bind_host = os.getenv("SENTINEL_BIND_HOST") or os.getenv("SENTINEL_HOST", "127.0.0.1")
    externally_bound = not _is_loopback_bind(bind_host)
    app.state.jwt_config = JWTConfig(
        secret=jwt_secret,
        issuer=os.getenv("SENTINEL_JWT_ISSUER") or None,
        audience=os.getenv("SENTINEL_JWT_AUDIENCE") or None,
        # Local development and the offline demo may use the synthetic principal,
        # but deployment-like environments must fail closed if JWT is missing.
        required=bool(jwt_secret) or production_like or externally_bound,
    )
    app.include_router(router)
    return app
