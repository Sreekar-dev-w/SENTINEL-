"""Safe URL parsing and canonical-origin construction.

This module performs no network access. It only validates and normalizes a
user-supplied target before later phases are allowed to resolve or connect to
it.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import SplitResult, urlsplit, urlunsplit


class URLValidationError(ValueError):
    """Raised when a target URL is not safe to use as a scan target."""


@dataclass(frozen=True, slots=True)
class NormalizedURL:
    """Canonical URL data used by later scope and connection policies."""

    url: str
    origin: str
    scheme: str
    hostname: str
    port: int
    path: str
    query: str

    @property
    def is_ip_literal(self) -> bool:
        """Return whether ``hostname`` is an IPv4 or IPv6 literal."""

        try:
            ip_address(self.hostname)
        except ValueError:
            return False
        return True


def _reject_control_or_whitespace(raw_url: str) -> None:
    if any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in raw_url):
        raise URLValidationError("URL must not contain whitespace or control characters")
    if "\\" in raw_url:
        raise URLValidationError("URL must not contain backslashes")


def _normalized_hostname(parsed: SplitResult) -> tuple[str, bool]:
    try:
        hostname = parsed.hostname
    except ValueError as exc:
        raise URLValidationError("URL contains an invalid hostname") from exc

    if not hostname:
        raise URLValidationError("URL must include a hostname")
    if "%" in hostname:
        raise URLValidationError("IPv6 zone identifiers are not accepted")

    hostname = hostname.rstrip(".")
    if not hostname:
        raise URLValidationError("URL must include a hostname")

    try:
        literal = ip_address(hostname)
    except ValueError:
        try:
            encoded = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLValidationError("URL hostname is not valid IDNA") from exc
        return encoded, False

    if isinstance(literal, IPv4Address):
        return str(literal), True
    if isinstance(literal, IPv6Address):
        return literal.compressed.lower(), True
    raise URLValidationError("URL hostname has an unsupported address type")


def _validated_port(parsed: SplitResult, scheme: str) -> int:
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise URLValidationError("URL contains an invalid port") from exc

    port = parsed_port if parsed_port is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise URLValidationError("URL port must be between 1 and 65535")
    return port


def _authority(hostname: str, port: int, scheme: str) -> str:
    display_hostname = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return display_hostname
    return f"{display_hostname}:{port}"


def normalize_target_url(raw_url: str) -> NormalizedURL:
    """Validate and normalize an HTTP(S) target URL.

    Fragments are removed because browsers do not send them to servers. The
    returned origin includes the scheme, normalized hostname, and effective
    port, making it suitable for same-origin enforcement in later phases.
    """

    if not isinstance(raw_url, str) or not raw_url:
        raise URLValidationError("URL must be a non-empty string")
    _reject_control_or_whitespace(raw_url)

    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        raise URLValidationError("URL could not be parsed") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise URLValidationError("Only http and https URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise URLValidationError("Embedded URL credentials are not allowed")
    if not parsed.netloc:
        raise URLValidationError("URL must include an authority")

    hostname, _ = _normalized_hostname(parsed)
    port = _validated_port(parsed, scheme)
    authority = _authority(hostname, port, scheme)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"

    normalized_url = urlunsplit((scheme, authority, path, parsed.query, ""))
    origin = f"{scheme}://{authority}"
    return NormalizedURL(
        url=normalized_url,
        origin=origin,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=parsed.query,
    )
