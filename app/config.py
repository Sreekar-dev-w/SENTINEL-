"""Typed configuration boundary for future scan orchestration.

Keeping limits in one pure module makes later network code consume explicit
policy rather than ad hoc constants. No network behavior is implemented here.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Conservative defaults for the bounded scan MVP and HTTP client."""

    request_timeout_seconds: float = 10.0
    scan_timeout_seconds: float = 30.0
    maximum_response_bytes: int = 2_000_000
    maximum_crawl_depth: int = 2
    maximum_pages: int = 50
    maximum_concurrency: int = 4
    maximum_requests_per_scan: int = 50
    maximum_findings: int = 100
    maximum_requests_per_host: int = 50
    maximum_redirects: int = 5
    allowed_ports: tuple[int, ...] = (80, 443)
