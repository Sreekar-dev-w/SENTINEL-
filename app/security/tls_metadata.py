"""Compatibility import path for the narrow TLS metadata boundary."""

from app.security.tls import (
    TLSMetadata,
    TLSMetadataProbe,
    TLSMetadataProvider,
    TLSProbe,
    TLSProbeRequest,
    TLSProbeResult,
    TLSMetadataResult,
    TLSProbeStatus,
    UnavailableTLSProbe,
    collect_tls_metadata,
)

__all__ = [
    "TLSMetadata",
    "TLSMetadataProbe",
    "TLSMetadataProvider",
    "TLSProbe",
    "TLSProbeRequest",
    "TLSProbeResult",
    "TLSMetadataResult",
    "TLSProbeStatus",
    "UnavailableTLSProbe",
    "collect_tls_metadata",
]
