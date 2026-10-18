"""HTTP routes for the v0.1 scan API.

Routes only validate HTTP input and delegate to an injected scan manager.  The
manager is intentionally not implemented here so this layer cannot initiate
network work by accident.
"""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Protocol

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError

from app.api.models import (
    CreateEngagementRequest,
    CreateScanRequest,
    EngagementResponse,
    ScanStatusResponse,
)
from app.engagement import EngagementNotFound, EngagementPolicyError, EngagementStore


class ScanManager(Protocol):
    """The async seam required by the API layer.

    Implementations may keep state in memory or use another application-owned
    mechanism.  They must not be constructed by this module.
    """

    async def create_scan(self, request: CreateScanRequest) -> Any:
        """Create and schedule one scan, returning its initial status."""

    async def get_scan(self, scan_id: str) -> Any | None:
        """Return a scan status, or ``None`` when the ID is unknown."""

    async def cancel_scan(self, scan_id: str) -> Any | None:
        """Request cancellation, or return ``None`` for an unknown scan."""


router = APIRouter(tags=["scans"])


def get_scan_manager(request: Request) -> ScanManager:
    """Resolve the application-owned manager through FastAPI DI."""

    manager = getattr(request.app.state, "scan_manager", None)
    if manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan manager is not configured",
        )
    return manager


async def _call_manager(operation: Awaitable[Any] | Any) -> Any:
    """Await an async manager result while keeping test doubles convenient."""

    if inspect.isawaitable(operation):
        return await operation
    return operation


def get_engagement_store(request: Request) -> EngagementStore:
    """Resolve the store next to the application-owned scan manager."""

    store = getattr(request.app.state, "engagement_store", None)
    if store is None:
        manager = getattr(request.app.state, "scan_manager", None)
        store = getattr(manager, "engagement_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Engagement store is not configured",
        )
    return store


@router.post(
    "/scans",
    response_model=ScanStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_scan(
    request: CreateScanRequest,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanStatusResponse:
    """Validate and enqueue an authorized scan through the injected manager."""

    try:
        result = await _call_manager(manager.create_scan(request))
    except EngagementNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found") from exc
    except EngagementPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return ScanStatusResponse.model_validate(result)


@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan(
    scan_id: str,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanStatusResponse:
    """Return the current status and results for a scan."""

    result = await _call_manager(manager.get_scan(scan_id))
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return ScanStatusResponse.model_validate(result)


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def cancel_scan(
    scan_id: str,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanStatusResponse:
    """Request cancellation through the injected manager."""

    result = await _call_manager(manager.cancel_scan(scan_id))
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return ScanStatusResponse.model_validate(result)


@router.post(
    "/engagements",
    response_model=EngagementResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_engagement(
    request: CreateEngagementRequest,
    store: EngagementStore = Depends(get_engagement_store),
) -> EngagementResponse:
    try:
        engagement = request.to_engagement()
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid engagement: {exc}",
        ) from exc
    result = await _call_manager(store.create(engagement))
    return EngagementResponse.model_validate(result)


@router.get("/engagements/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement_id: str,
    store: EngagementStore = Depends(get_engagement_store),
) -> EngagementResponse:
    result = await _call_manager(store.get(engagement_id))
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found")
    return EngagementResponse.model_validate(result)


@router.post(
    "/engagements/{engagement_id}/cancel",
    response_model=EngagementResponse,
)
async def cancel_engagement(
    engagement_id: str,
    store: EngagementStore = Depends(get_engagement_store),
) -> EngagementResponse:
    try:
        result = await _call_manager(store.cancel(engagement_id))
    except EngagementNotFound as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found") from exc
    return EngagementResponse.model_validate(result)
