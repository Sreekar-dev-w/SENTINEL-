"""FastAPI application factory for SENTINEL's API contract layer."""

from __future__ import annotations

import os

from fastapi import FastAPI

from app.api.routes import ScanManager, router
from app.assessment.lab import build_secure_application_security_lab
from app.external_tools import NmapAdapter, TestSSLAdapter, ZAPAdapter, ZAPHTTPTransport
from app.reporting import ReportExporter


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
    app.state.scan_manager = scan_manager
    app.state.engagement_store = getattr(scan_manager, "engagement_store", None)
    app.state.report_exporter = ReportExporter()
    app.include_router(router)
    return app
