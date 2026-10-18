"""Bounded, same-origin website intelligence for the v0.2 scan flow.

This module is intentionally a small companion to :mod:`http_client`: it does
not create a transport, resolve arbitrary links, submit forms, or execute
JavaScript.  Every page request is made through the scan's existing client and
the scan's existing budget.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.scanning.budget import RequestBudgetExhausted, ScanBudget, ScanDeadlineExceeded
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.models import (
    FindingConfidence,
    MinimalEvidence,
    ObservationMode,
    ObservationStatus,
    WebsiteObservation,
    WebsiteProfile,
    WebsiteResource,
    WebsiteSummary,
)
from app.security.dns import resolve_validated_destination
from app.security.url_validation import URLValidationError, normalize_target_url


_MAX_DISCOVERED_CANDIDATES = 1_000
_SENSITIVE_QUERY_MARKER = "[redacted]"


def redact_url(url: str) -> str:
    """Return a display-safe URL with every query value replaced.

    Query parameter names can still be useful evidence, while values are never
    returned or logged.  Fragments are removed because they are not sent over
    HTTP.  Invalid candidates are not passed to this helper by the engine.
    """

    parsed = urlsplit(url)
    if not parsed.query:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    redacted_parts: list[str] = []
    for item in parsed.query.split("&"):
        if not item:
            continue
        key = item.split("=", 1)[0]
        redacted_parts.append(f"{key}={_SENSITIVE_QUERY_MARKER}")
    query = "&".join(redacted_parts)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))


def _request_url(normalized_url: str) -> str:
    """Build a safe discovery request URL without sending query values."""

    parsed = urlsplit(normalized_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _content_type(response: httpx.Response) -> str:
    value = response.headers.get("content-type", "")
    return value[:512]


def _is_html(response: httpx.Response) -> bool:
    return "text/html" in _content_type(response).lower() or "application/xhtml+xml" in _content_type(response).lower()


def _evidence(response: httpx.Response, *, url: str | None = None) -> MinimalEvidence:
    headers: dict[str, str] = {}
    content_type = response.headers.get("content-type")
    if content_type:
        headers["content-type"] = content_type[:4096]
    location = response.headers.get("location")
    if location:
        try:
            location_normalized = normalize_target_url(urljoin(str(response.url), location))
            headers["location"] = redact_url(location_normalized.url)
        except (TypeError, ValueError, URLValidationError):
            headers["location"] = "[redacted-invalid-location]"
    return MinimalEvidence(
        url=redact_url(url or str(response.url)),
        status_code=response.status_code,
        headers=headers,
    )


@dataclass(frozen=True, slots=True)
class _Candidate:
    raw_url: str
    kind: str
    depth: int
    source_url: str
    method: str | None = None
    fields: tuple[str, ...] = ()


class _HTMLDiscoveryParser(HTMLParser):
    """Extract URL-bearing HTML attributes without interpreting page code."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.candidates: list[tuple[str, str, str | None, tuple[str, ...]]] = []
        self._form_stack: list[dict[str, object]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if len(self.candidates) >= _MAX_DISCOVERED_CANDIDATES:
            return
        attributes = {name.lower(): value for name, value in attrs}
        tag_name = tag.lower()
        if tag_name == "form":
            self._form_stack.append(
                {
                    "action": attributes.get("action") or "",
                    "method": (attributes.get("method") or "get").upper(),
                    "fields": [],
                }
            )
            return
        if self._form_stack and tag_name in {"input", "textarea", "select", "button"}:
            name = (attributes.get("name") or "").strip()
            if name and isinstance(self._form_stack[-1]["fields"], list):
                self._form_stack[-1]["fields"].append(name)
            return
        if tag_name == "a" and attributes.get("href"):
            self.candidates.append((attributes["href"] or "", "link", None, ()))
        elif tag_name == "script" and attributes.get("src"):
            self.candidates.append((attributes["src"] or "", "script", None, ()))
        elif tag_name == "link" and attributes.get("href"):
            rel = (attributes.get("rel") or "").lower().split()
            kind = "style" if "stylesheet" in rel else "link"
            if "sitemap" in rel or "robots" in rel:
                kind = "sitemap" if "sitemap" in rel else "robots"
            self.candidates.append((attributes["href"] or "", kind, None, ()))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form_stack:
            form = self._form_stack.pop()
            fields = form["fields"] if isinstance(form["fields"], list) else []
            self.candidates.append(
                (
                    str(form["action"]),
                    "form",
                    str(form["method"]),
                    tuple(str(field) for field in fields),
                )
            )


def _parse_html(body: bytes) -> list[tuple[str, str, str | None, tuple[str, ...]]]:
    parser = _HTMLDiscoveryParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, TypeError):
        # Hostile/malformed markup is an optional intelligence failure, not a
        # scan failure.  Already parsed safe candidates remain useful.
        return parser.candidates
    return parser.candidates


def _parse_reference_document(body: bytes, *, sitemap: bool) -> Iterable[str]:
    """Extract only explicit sitemap references from robots/XML text."""

    text = body.decode("utf-8", errors="replace")
    if sitemap:
        for match in re.finditer(r"<loc\b[^>]*>\s*(.*?)\s*</loc\s*>", text, re.IGNORECASE | re.DOTALL):
            value = unescape(match.group(1)).strip()
            if value:
                yield value[:4096]
        return
    for line in text.splitlines():
        if line.lower().startswith("sitemap:"):
            value = line.split(":", 1)[1].strip()
            if value:
                yield value[:4096]


class WebsiteIntelligenceEngine:
    """Collect a bounded website profile using one client and one budget."""

    async def scan(
        self,
        target_url: str,
        initial_response: httpx.Response,
        client: BoundedHTTPClient,
        budget: ScanBudget,
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> WebsiteProfile:
        target = normalize_target_url(target_url)
        profile = WebsiteProfile(
            initial_url=redact_url(target.url),
            final_url=redact_url(str(initial_response.url)),
        )
        observations: list[WebsiteObservation] = []
        resources: list[WebsiteResource] = []
        queue: deque[_Candidate] = deque()
        seen_requests: set[str] = {_request_url(target.url)}
        seen_resources: set[str] = set()
        pages_scanned = 1
        resources_scanned = 0
        cross_origin_blocked = 0
        partial = False

        observations.append(
            WebsiteObservation(
                kind="domain.target",
                value={"hostname": target.hostname, "scheme": target.scheme, "origin": target.origin},
                mode=ObservationMode.OBSERVED,
                confidence=FindingConfidence.HIGH,
                status=ObservationStatus.OBSERVED,
                evidence=MinimalEvidence(url=redact_url(target.url)),
            )
        )
        observations.append(self._page_observation(initial_response))
        observations.extend(self._redirect_observations(initial_response))
        observations.extend(self._technology_observations(initial_response))
        observations.extend(await self._dns_observations(target, client))
        observations.extend(self._unavailable_observations())

        if _is_html(initial_response):
            queue.extend(
                self._candidates_from_response(
                    initial_response, depth=1, source_url=str(initial_response.url)
                )
            )

        while queue:
            await self._check_cancel(cancel_event)
            candidate = queue.popleft()
            try:
                normalized = normalize_target_url(urljoin(candidate.source_url, candidate.raw_url))
            except (TypeError, ValueError, URLValidationError):
                continue

            display_url = redact_url(normalized.url)
            request_url = _request_url(normalized.url)
            if request_url in seen_resources:
                continue
            seen_resources.add(request_url)
            evidence = MinimalEvidence(url=display_url)

            if normalized.origin != target.origin:
                cross_origin_blocked += 1
                resources.append(
                    WebsiteResource(
                        url=display_url,
                        kind=candidate.kind,
                        depth=candidate.depth,
                        confidence=FindingConfidence.HIGH,
                        status=ObservationStatus.LIMITED,
                        evidence=evidence,
                    )
                )
                partial = True
                continue
            if candidate.kind == "form":
                # Recording an action is useful intelligence, but even a GET
                # to a form action can have side effects.  Never submit it.
                resources.append(
                    WebsiteResource(
                        url=display_url,
                        kind=candidate.kind,
                        depth=candidate.depth,
                        status=ObservationStatus.LIMITED,
                        method=candidate.method,
                        fields=list(candidate.fields),
                        source_url=redact_url(candidate.source_url),
                        evidence=evidence,
                    )
                )
                partial = True
                continue
            if candidate.depth > client.limits.maximum_crawl_depth:
                resources.append(
                    WebsiteResource(
                        url=display_url,
                        kind=candidate.kind,
                        depth=candidate.depth,
                        status=ObservationStatus.LIMITED,
                        evidence=evidence,
                    )
                )
                partial = True
                continue
            if request_url in seen_requests:
                continue
            if pages_scanned >= client.limits.maximum_pages:
                resources.append(
                    WebsiteResource(
                        url=display_url,
                        kind=candidate.kind,
                        depth=candidate.depth,
                        status=ObservationStatus.LIMITED,
                        evidence=evidence,
                    )
                )
                partial = True
                continue

            resource_index = len(resources)
            resources.append(
                WebsiteResource(
                    url=display_url,
                    kind=candidate.kind,
                    depth=candidate.depth,
                    status=ObservationStatus.INCONCLUSIVE,
                    evidence=evidence,
                )
            )
            seen_requests.add(request_url)
            # Reserve a page slot before the network attempt so repeated
            # failures cannot bypass the scan-wide page bound.
            pages_scanned += 1
            try:
                async with budget.attempt():
                    response = await client.get(request_url)
            except (RequestBudgetExhausted, ScanDeadlineExceeded):
                resources[resource_index] = resources[resource_index].model_copy(
                    update={"status": ObservationStatus.LIMITED}
                )
                partial = True
                continue
            except asyncio.CancelledError:
                raise
            except Exception:
                resources[resource_index] = resources[resource_index].model_copy(
                    update={"status": ObservationStatus.ERROR}
                )
                partial = True
                continue

            try:
                resources_scanned += 1
                resources[resource_index] = resources[resource_index].model_copy(
                    update={
                        "status": ObservationStatus.OBSERVED,
                        "evidence": _evidence(response, url=request_url),
                    }
                )
                observations.append(self._page_observation(response))
                observations.extend(self._technology_observations(response))
                if _is_html(response):
                    queue.extend(
                        self._candidates_from_response(
                            response, depth=candidate.depth + 1, source_url=str(response.url)
                        )
                    )
                if self._is_robots(response):
                    for reference in _parse_reference_document(response.content, sitemap=False):
                        queue.append(_Candidate(reference, "sitemap", candidate.depth + 1, str(response.url)))
                elif self._is_sitemap(response):
                    for reference in _parse_reference_document(response.content, sitemap=True):
                        queue.append(_Candidate(reference, "sitemap", candidate.depth + 1, str(response.url)))
            finally:
                response.close()

        if queue:
            partial = True
        summary = WebsiteSummary(
            pages_scanned=pages_scanned,
            resources_discovered=len(resources),
            resources_scanned=resources_scanned,
            cross_origin_blocked=cross_origin_blocked,
            observations_total=len(observations),
            partial=partial,
        )
        profile.observations = observations
        profile.resources = resources
        profile.summary = summary
        profile.status = ObservationStatus.INCONCLUSIVE if partial else ObservationStatus.OBSERVED
        profile.confidence = FindingConfidence.MEDIUM if partial else FindingConfidence.HIGH
        return profile

    @staticmethod
    async def _check_cancel(cancel_event: asyncio.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError
        await asyncio.sleep(0)

    @staticmethod
    def _page_observation(response: httpx.Response) -> WebsiteObservation:
        body = response.content
        title_match = re.search(rb"<title\b[^>]*>(.*?)</title\s*>", body, re.IGNORECASE | re.DOTALL)
        canonical_match = re.search(
            rb"<link\b[^>]*rel\s*=\s*['\"]?canonical['\"]?[^>]*href\s*=\s*['\"]([^'\"]+)",
            body,
            re.IGNORECASE,
        )
        title = title_match.group(1).decode("utf-8", errors="replace").strip()[:512] if title_match else None
        canonical = canonical_match.group(1).decode("utf-8", errors="replace").strip()[:2048] if canonical_match else None
        value: dict[str, str | int | bool | list[str]] = {
            "status_code": response.status_code,
            "content_type": _content_type(response),
        }
        if title:
            value["title"] = title
        if canonical:
            try:
                value["canonical_url"] = redact_url(normalize_target_url(urljoin(str(response.url), canonical)).url)
            except (TypeError, ValueError, URLValidationError):
                pass
        return WebsiteObservation(
            kind="page",
            value=value,
            mode=ObservationMode.OBSERVED,
            confidence=FindingConfidence.HIGH,
            status=ObservationStatus.OBSERVED,
            evidence=_evidence(response),
        )

    @staticmethod
    def _redirect_observations(response: httpx.Response) -> list[WebsiteObservation]:
        observations: list[WebsiteObservation] = []
        for previous in response.history:
            location = previous.headers.get("location")
            if not location:
                continue
            target = urljoin(str(previous.url), location)
            try:
                target = redact_url(normalize_target_url(target).url)
            except (TypeError, ValueError, URLValidationError):
                target = "[redacted-invalid-location]"
            observations.append(
                WebsiteObservation(
                    kind="http.redirect",
                    value={
                        "from": redact_url(str(previous.url)),
                        "to": target,
                        "status_code": previous.status_code,
                        "followed": True,
                    },
                    mode=ObservationMode.OBSERVED,
                    confidence=FindingConfidence.HIGH,
                    status=ObservationStatus.OBSERVED,
                    evidence=_evidence(previous),
                )
            )
        return observations

    @staticmethod
    def _technology_observations(response: httpx.Response) -> list[WebsiteObservation]:
        observations: list[WebsiteObservation] = []
        for header, category in (("server", "web_server"), ("x-powered-by", "server_framework")):
            value = response.headers.get(header)
            if value:
                observations.append(
                    WebsiteObservation(
                        kind=f"technology.{category}",
                        value={"name": value[:256], "source": header},
                        mode=ObservationMode.OBSERVED,
                        confidence=FindingConfidence.MEDIUM,
                        status=ObservationStatus.OBSERVED,
                        evidence=_evidence(response),
                    )
                )
        edge_headers = [header for header in ("cf-ray", "x-cache", "via") if response.headers.get(header)]
        if edge_headers:
            observations.append(
                WebsiteObservation(
                    kind="infrastructure.edge_indicators",
                    value={"headers": edge_headers},
                    mode=ObservationMode.INFERRED,
                    confidence=FindingConfidence.MEDIUM,
                    status=ObservationStatus.INFERRED,
                    evidence=_evidence(response),
                )
            )
        return observations

    @staticmethod
    async def _dns_observations(target, client: BoundedHTTPClient) -> list[WebsiteObservation]:
        evidence = MinimalEvidence(url=redact_url(target.url))
        if target.is_ip_literal:
            return [
                WebsiteObservation(
                    kind="dns.a_aaaa",
                    value={"addresses": [target.hostname]},
                    mode=ObservationMode.OBSERVED,
                    confidence=FindingConfidence.HIGH,
                    status=ObservationStatus.OBSERVED,
                    evidence=evidence,
                )
            ]
        try:
            destination = await resolve_validated_destination(target.hostname, client.resolver)
        except Exception:
            return [
                WebsiteObservation(
                    kind="dns.a_aaaa",
                    mode=ObservationMode.OBSERVED,
                    confidence=FindingConfidence.LOW,
                    status=ObservationStatus.INCONCLUSIVE,
                    evidence=evidence,
                )
            ]
        return [
            WebsiteObservation(
                kind="dns.a_aaaa",
                value={"addresses": list(destination.addresses)},
                mode=ObservationMode.OBSERVED,
                confidence=FindingConfidence.HIGH,
                status=ObservationStatus.OBSERVED,
                evidence=evidence,
            )
        ]

    @staticmethod
    def _unavailable_observations() -> list[WebsiteObservation]:
        return [
            WebsiteObservation(
                kind=kind,
                mode=ObservationMode.INFERRED,
                confidence=FindingConfidence.LOW,
                status=ObservationStatus.UNAVAILABLE,
            )
            for kind in ("dns.mx", "dns.ns", "dns.txt", "asn.provider", "tls.certificate")
        ]

    @staticmethod
    def _candidates_from_response(
        response: httpx.Response, *, depth: int, source_url: str
    ) -> Iterable[_Candidate]:
        for raw_url, kind, method, fields in _parse_html(response.content):
            if len(raw_url) > 4096:
                continue
            lower = raw_url.lower().split("?", 1)[0].split("#", 1)[0]
            if lower.endswith("robots.txt"):
                kind = "robots"
            elif "sitemap" in lower and lower.endswith((".xml", ".txt")):
                kind = "sitemap"
            yield _Candidate(raw_url, kind, depth, source_url, method, fields)

    @staticmethod
    def _is_robots(response: httpx.Response) -> bool:
        return urlsplit(str(response.url)).path.lower().rstrip("/").endswith("/robots.txt")

    @staticmethod
    def _is_sitemap(response: httpx.Response) -> bool:
        path = urlsplit(str(response.url)).path.lower()
        return "sitemap" in path and path.endswith((".xml", ".txt"))


IntelligenceEngine = WebsiteIntelligenceEngine
