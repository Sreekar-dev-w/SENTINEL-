"""Typed external-tool adapter contracts and approved integrations."""

from app.external_tools.contracts import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    AdapterScope,
    ExternalToolAdapter,
    ExternalToolAvailability,
    ExternalToolExecutionState,
    ExternalToolFinding,
    ExternalToolIdentity,
    ExternalToolTransport,
    ExecutionState,
    FindingProvenance,
    NormalizedFinding,
    NormalizedObservation,
    SanitizedDiagnostic,
    ScopeRequirement,
    ToolAvailability,
    ToolAvailabilityStatus,
    ToolCapability,
    ToolHTTPResponse,
    ToolIdentity,
)
from app.external_tools.nmap import (
    NMAP_DISCOVERY_CAPABILITY,
    NMAP_SERVICE_CAPABILITY,
    NmapAdapter,
    NmapExternalToolAdapter,
)
from app.external_tools.process import (
    ProcessResult,
    ProcessRunner,
    ProcessUnavailable,
    SubprocessRunner,
)
from app.external_tools.testssl import (
    TESTSSL_CAPABILITY,
    TestSSLAdapter,
    TestSSLExternalToolAdapter,
    TestsslAdapter,
)
from app.external_tools.zap import (
    ZAP_ACTIVE_SCAN_CAPABILITY,
    ZAPAdapter,
    ZAPHTTPTransport,
    ZAPTransportError,
)
from app.external_tools.registry import (
    ExternalToolRegistry,
    ExternalToolRunner,
    ExternalToolSelectionError,
)

ZAPExternalToolAdapter = ZAPAdapter

__all__ = [
    "AdapterExecutionRequest",
    "AdapterExecutionResult",
    "AdapterScope",
    "ExternalToolAdapter",
    "ExternalToolAvailability",
    "ExternalToolExecutionState",
    "ExternalToolFinding",
    "ExternalToolIdentity",
    "ExternalToolTransport",
    "ExecutionState",
    "FindingProvenance",
    "NormalizedFinding",
    "NormalizedObservation",
    "SanitizedDiagnostic",
    "ScopeRequirement",
    "ToolAvailability",
    "ToolAvailabilityStatus",
    "ToolCapability",
    "ToolHTTPResponse",
    "ToolIdentity",
    "ZAP_ACTIVE_SCAN_CAPABILITY",
    "ZAPAdapter",
    "ZAPExternalToolAdapter",
    "ZAPHTTPTransport",
    "ZAPTransportError",
    "ExternalToolRegistry",
    "ExternalToolRunner",
    "ExternalToolSelectionError",
    "NMAP_DISCOVERY_CAPABILITY",
    "NMAP_SERVICE_CAPABILITY",
    "NmapAdapter",
    "NmapExternalToolAdapter",
    "ProcessResult",
    "ProcessRunner",
    "ProcessUnavailable",
    "SubprocessRunner",
    "TESTSSL_CAPABILITY",
    "TestSSLAdapter",
    "TestSSLExternalToolAdapter",
    "TestsslAdapter",
]
