"""Shared helper for EpiGraph bootstrap scripts to call the HTTP API.

Mints a short-lived HS256 JWT using EPIGRAPH_JWT_SECRET (matches the test
helper `test_bearer_token_with_scopes` in
crates/epigraph-api/tests/common/mod.rs) and provides a tiny `EpiGraphClient`
that wraps `requests` with automatic bearer auth + URL prefix.

Per feedback_no_raw_sql.md: bootstrap scripts should call the API, not write
raw SQL.

Environment:
    EPIGRAPH_API_BASE       e.g. "http://127.0.0.1:8080"
    EPIGRAPH_JWT_SECRET     shared HS256 secret; falls back to the dev default
                            ("epigraph-dev-secret-change-in-production!!")

Usage:
    from _api_client import EpiGraphClient
    c = EpiGraphClient(scopes=["claims:admin"])
    r = c.patch("/api/v1/claims/<uuid>", json={"properties": {"x": 1}})
    r.raise_for_status()
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Optional

import jwt
import requests

DEFAULT_API_BASE = "http://127.0.0.1:8080"
DEFAULT_JWT_SECRET = "epigraph-dev-secret-change-in-production!!"


def mint_bearer_token(
    scopes: list[str],
    client_id: Optional[uuid.UUID] = None,
    ttl_seconds: int = 3600,
    client_type: str = "service",
    agent_id: Optional[uuid.UUID] = None,
    owner_id: Optional[uuid.UUID] = None,
) -> str:
    """Issue an HS256 JWT matching the shape produced by epigraph_auth::JwtConfig.

    Mirror of epigraph-auth/src/lib.rs::JwtConfig::issue_access_token:
      claims: {sub, iss="epigraph", aud="epigraph-api", exp, iat, nbf, jti,
               scopes, client_type, owner_id?, agent_id?}
      algorithm: HS256
    """
    secret = os.environ.get("EPIGRAPH_JWT_SECRET", DEFAULT_JWT_SECRET)
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": str(client_id or uuid.uuid4()),
        "iss": "epigraph",
        "aud": "epigraph-api",
        "exp": now + ttl_seconds,
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "scopes": scopes,
        "client_type": client_type,
        "owner_id": str(owner_id) if owner_id else None,
        "agent_id": str(agent_id) if agent_id else None,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


class EpiGraphClient:
    """Thin requests wrapper with automatic bearer auth + API base URL.

    Raises HTTPError on non-2xx responses (caller can choose to ignore via
    response.status_code check before raise_for_status()).
    """

    def __init__(
        self,
        scopes: Optional[list[str]] = None,
        base: Optional[str] = None,
        timeout: float = 60.0,
    ):
        self.base = (base or os.environ.get("EPIGRAPH_API_BASE", DEFAULT_API_BASE)).rstrip("/")
        self.token = mint_bearer_token(scopes or ["claims:read"])
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def get(self, path: str, **kw: Any) -> requests.Response:
        return requests.get(self.base + path, headers=self._headers(), timeout=self.timeout, **kw)

    def post(self, path: str, **kw: Any) -> requests.Response:
        return requests.post(self.base + path, headers=self._headers(), timeout=self.timeout, **kw)

    def patch(self, path: str, **kw: Any) -> requests.Response:
        return requests.patch(self.base + path, headers=self._headers(), timeout=self.timeout, **kw)

    def delete(self, path: str, **kw: Any) -> requests.Response:
        return requests.delete(self.base + path, headers=self._headers(), timeout=self.timeout, **kw)
