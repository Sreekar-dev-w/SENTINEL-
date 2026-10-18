"""FastAPI application factory for SENTINEL's API contract layer."""

from __future__ import annotations

from fastapi import FastAPI

from app.api.routes import ScanManager, router
from app.reporting import ReportExporter


def create_app(scan_manager: ScanManager | None = None) -> FastAPI:
    """Build an API application with an application-owned manager.

    Passing ``scan_manager`` is the normal integration seam.  Leaving it out
    is useful for importing the contract or mounting the router before the
    runner wires its manager; requests then receive a clear 503 response.
    """

    if scan_manager is None:
        from app.scanning.runner import ScanManager

        scan_manager = ScanManager()

    app = FastAPI(title="SENTINEL API", version="0.1.0")
    app.state.scan_manager = scan_manager
    app.state.engagement_store = getattr(scan_manager, "engagement_store", None)
    app.state.report_exporter = ReportExporter()
    app.include_router(router)
    return app
