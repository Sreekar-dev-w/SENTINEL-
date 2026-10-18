"""The deliberately small, metadata-only execution context for modules."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from urllib.parse import urljoin

import httpx

from app.scanning.budget import ScanBudget
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.intelligence import redact_url
from app.scanning.models import WebsiteProfile
from app.security.url_validation import URLValidationError, normalize_target_url


@dataclass(frozen=True, slots=True)
class CookieSnapshot:
    """Cookie attribute metadata with the name and value deliberately absent."""

    secure: bool
    httponly: bool
    samesite: str | None
    malformed: bool = False


@dataclass(frozen=True, slots=True)
class RedirectSnapshot:
    url: str
    location: str
    status_code: int


_SAFE_HEADERS = frozenset({
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "vary",
    "content-type",
    "location",
    "server",
    "x-powered-by",
    "via",
    "x-cache",
    "cf-ray",
})


@dataclass(frozen=True, slots=True)
class ResponseSnapshot:
    """Safe response metadata exposed to assessment modules.

    No response body, raw cookie value, authorization material, or unrestricted
    header map is retained. The snapshot is the only response object modules
    receive.
    """

    url: str
    status_code: int
    headers: tuple[tuple[str, str], ...] = ()
    cookies: tuple[CookieSnapshot, ...] = ()
    malformed_cookies: int = 0
    history: tuple[RedirectSnapshot, ...] = ()

    @classmethod
    def from_response(cls, response: httpx.Response) -> "ResponseSnapshot":
        safe_headers = tuple(
            (name.lower(), str(response.headers[name])[:4096])
            for name in _SAFE_HEADERS
            if name in response.headers
        )
        cookies: list[CookieSnapshot] = []
        malformed = 0
        for line in response.headers.get_list("set-cookie"):
            parsed = SimpleCookie()
            try:
                parsed.load(line)
            except (TypeError, ValueError):
                parsed = SimpleCookie()
            if not parsed:
                malformed += 1
                continue
            for morsel in parsed.values():
                cookies.append(CookieSnapshot(
                    secure=bool(morsel["secure"]),
                    httponly=bool(morsel["httponly"]),
                    samesite=(morsel["samesite"] or None),
                ))
        history: list[RedirectSnapshot] = []
        for previous in response.history:
            location = previous.headers.get("location")
            if not location:
                continue
            try:
                safe_location = redact_url(urljoin(str(previous.url), location))
            except (TypeError, ValueError):
                safe_location = "[redacted-invalid-location]"
            history.append(RedirectSnapshot(
                url=redact_url(str(previous.url)),
                location=safe_location,
                status_code=previous.status_code,
            ))
        return cls(
            url=redact_url(str(response.url)),
            status_code=response.status_code,
            headers=safe_headers,
            cookies=tuple(cookies),
            malformed_cookies=malformed,
            history=tuple(history),
        )

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        return next((value for key, value in self.headers if key == wanted), None)

    def has_header(self, name: str) -> bool:
        return self.header(name) is not None


@dataclass(frozen=True, slots=True)
class AssessmentContext:
    """A safe response snapshot plus policy-controlled future request access."""

    target_url: str
    response: ResponseSnapshot | httpx.Response
    budget: ScanBudget
    intelligence: WebsiteProfile | None = None
    cancel_event: asyncio.Event | None = None
    prerequisites: frozenset[str] = field(default_factory=frozenset)
    capabilities: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=lambda: frozenset({"authorized-target"}))
    _client: BoundedHTTPClient | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Keep a source-compatible constructor for deterministic tests and
        # embedding callers, but never expose the raw response to a module.
        if isinstance(self.response, httpx.Response):
            object.__setattr__(self, "response", ResponseSnapshot.from_response(self.response))

    def has_prerequisite(self, name: str) -> bool:
        return name in self.prerequisites

    async def get_same_origin(self, url: str) -> ResponseSnapshot:
        """Make a policy-bound GET and return metadata only."""

        try:
            target = normalize_target_url(self.target_url)
            candidate = normalize_target_url(url)
        except (TypeError, ValueError, URLValidationError) as exc:
            raise ValueError("assessment request URL is invalid") from exc
        if candidate.origin != target.origin:
            raise ValueError("assessment requests must remain same-origin")
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise asyncio.CancelledError
        if self._client is None:
            raise RuntimeError("assessment request capability is not configured")
        if candidate.port not in self._client.limits.allowed_ports:
            raise ValueError("assessment request port is outside the configured scope")
        async with self.budget.attempt():
            response = await self._client.get(candidate.url)
        try:
            return ResponseSnapshot.from_response(response)
        finally:
            response.close()


AssessmentExecutionContext = AssessmentContext
