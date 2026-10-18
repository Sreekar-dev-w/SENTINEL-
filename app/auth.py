"""Dependency-free bearer JWT validation for trusted deployments.

This validates HS256 tokens issued by a configured gateway or OIDC integration.
SENTINEL does not fetch remote discovery documents during scan requests.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


class AuthenticationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    tenant: str = "default"
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class JWTConfig:
    secret: str | None = None
    issuer: str | None = None
    audience: str | None = None
    required: bool = False


def _part(value: str) -> dict[str, Any]:
    try:
        decoded = base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
        result = json.loads(decoded)
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthenticationError("malformed bearer token") from exc
    if not isinstance(result, dict):
        raise AuthenticationError("malformed bearer token")
    return result


def validate_bearer(token: str, config: JWTConfig) -> Principal:
    if not config.secret:
        raise AuthenticationError("JWT authentication is not configured")
    pieces = token.split(".")
    if len(pieces) != 3:
        raise AuthenticationError("malformed bearer token")
    header, claims = _part(pieces[0]), _part(pieces[1])
    if header.get("alg") != "HS256" or header.get("typ", "JWT") != "JWT":
        raise AuthenticationError("unsupported bearer token algorithm")
    expected = hmac.new(config.secret.encode(), f"{pieces[0]}.{pieces[1]}".encode(), hashlib.sha256).digest()
    try:
        actual = base64.urlsafe_b64decode((pieces[2] + "=" * (-len(pieces[2]) % 4)).encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise AuthenticationError("malformed bearer token") from exc
    if not hmac.compare_digest(expected, actual):
        raise AuthenticationError("invalid bearer token")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise AuthenticationError("bearer token subject is required")
    if config.issuer and claims.get("iss") != config.issuer:
        raise AuthenticationError("bearer token issuer is invalid")
    audience = claims.get("aud")
    if config.audience and audience != config.audience and not (isinstance(audience, list) and config.audience in audience):
        raise AuthenticationError("bearer token audience is invalid")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time():
        raise AuthenticationError("bearer token is expired")
    roles = claims.get("roles", claims.get("scope", []))
    if isinstance(roles, str):
        roles = roles.split()
    if not isinstance(roles, list):
        roles = []
    tenant = claims.get("tenant", claims.get("org_id", "default"))
    if not isinstance(tenant, str) or not tenant.strip():
        raise AuthenticationError("bearer token tenant is invalid")
    return Principal(subject=subject.strip(), tenant=tenant.strip(), roles=frozenset(str(role) for role in roles))


__all__ = ["AuthenticationError", "JWTConfig", "Principal", "validate_bearer"]
