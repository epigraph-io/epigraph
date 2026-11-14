"""Shared helper for EpiGraph bootstrap scripts to call the HTTP API.

Provides a tiny `EpiGraphClient` that wraps `requests` with bearer auth and the
API base URL. The bearer token comes from OAuth, never from this process:

  1. `EPIGRAPH_TOKEN`, when set and non-empty, is used as given (an operator
     minted it through /oauth/token). Its scopes are NOT checked here: a token
     missing one the job needs fails with a 403 at the request that needs it;
  2. otherwise `EPIGRAPH_SERVICE_CLIENT_ID` + `EPIGRAPH_SERVICE_SECRET` are
     exchanged at the token endpoint with the `client_credentials` grant, the
     same resolution `decompose_claims` uses;
  3. otherwise the client refuses to start.

It deliberately does not sign tokens itself. Signing with the server's HS256
secret made every script holding that secret a universal principal: any scope,
any `agent_id`, outside the per-client grants (backlog 3e927af3). Through the
token endpoint the server decides the scopes (the request intersected with the
client's grants) and the `agent_id` (the client's own agent), so a script can
do only what its OAuth client was granted.

Per feedback_no_raw_sql.md: bootstrap scripts should call the API, not write
raw SQL.

Environment:
    EPIGRAPH_API_BASE           e.g. "http://127.0.0.1:8080"
    EPIGRAPH_TOKEN              a bearer token, used verbatim
    EPIGRAPH_SERVICE_CLIENT_ID  a service client's client_id, and
    EPIGRAPH_SERVICE_SECRET     its secret, exchanged when EPIGRAPH_TOKEN is unset
    EPIGRAPH_OAUTH_TOKEN_URL    the token endpoint; default <API base>/oauth/token

Usage:
    from _api_client import EpiGraphClient
    c = EpiGraphClient(scopes=["claims:write"])
    r = c.patch("/api/v1/claims/<uuid>", json={"properties": {"x": 1}})
    r.raise_for_status()

    # Print a token for a script that reads EPIGRAPH_TOKEN:
    EPIGRAPH_SERVICE_CLIENT_ID=... EPIGRAPH_SERVICE_SECRET=... \\
        python3 scripts/_api_client.py claims:read claims:write
"""

from __future__ import annotations

import os
import sys
from typing import Any, Optional

import requests

DEFAULT_API_BASE = "http://127.0.0.1:8080"


def _env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value if value else None


def resolve_api_base(base: Optional[str] = None) -> str:
    return (base or _env("EPIGRAPH_API_BASE") or DEFAULT_API_BASE).rstrip("/")


def fetch_service_token(
    client_id: str,
    client_secret: str,
    token_url: str,
    scopes: list[str],
    timeout: float = 30.0,
) -> str:
    """Exchange service-client credentials for a bearer token
    (`grant_type=client_credentials`, form-encoded, as decompose_claims sends).

    Exits when the endpoint refuses, answers without an `access_token`, or
    grants fewer scopes than requested: the server drops ungranted scopes
    silently, and a job that needs one should stop here rather than 403
    partway through. No message includes the secret.
    """
    try:
        resp = requests.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": " ".join(scopes),
            },
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise SystemExit(f"token endpoint {token_url} unreachable: {type(e).__name__}")
    if not resp.ok:
        raise SystemExit(
            f"token endpoint {token_url} refused client {client_id!r}: HTTP {resp.status_code}"
        )
    try:
        body = resp.json()
    except ValueError:
        body = None
    token = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        raise SystemExit(f"token endpoint {token_url} returned no access_token")
    granted = set(str(body.get("scope") or "").split())
    missing = [s for s in scopes if s not in granted]
    if missing:
        raise SystemExit(
            f"client {client_id!r} was not granted {' '.join(missing)} "
            f"(granted: {' '.join(sorted(granted)) or 'none'})"
        )
    return token


def resolve_bearer_token(scopes: list[str], base: Optional[str] = None) -> str:
    """EPIGRAPH_TOKEN as given, else a client_credentials exchange, else exit.

    Only the exchange checks `scopes` (fetch_service_token exits when one was
    not granted). EPIGRAPH_TOKEN is opaque to this helper and is used without
    a scope check.
    """
    token = _env("EPIGRAPH_TOKEN")
    if token:
        return token
    client_id = _env("EPIGRAPH_SERVICE_CLIENT_ID")
    client_secret = _env("EPIGRAPH_SERVICE_SECRET")
    if not (client_id and client_secret):
        raise SystemExit(
            "No API credentials.\n"
            "Set EPIGRAPH_TOKEN to a token minted through /oauth/token, or set\n"
            "EPIGRAPH_SERVICE_CLIENT_ID and EPIGRAPH_SERVICE_SECRET to a service\n"
            "client granted the scopes this job needs; the token is then exchanged\n"
            "at EPIGRAPH_OAUTH_TOKEN_URL (default <API base>/oauth/token).\n"
            "This helper no longer signs its own tokens from EPIGRAPH_JWT_SECRET."
        )
    token_url = _env("EPIGRAPH_OAUTH_TOKEN_URL") or f"{resolve_api_base(base)}/oauth/token"
    return fetch_service_token(client_id, client_secret, token_url, scopes)


class EpiGraphClient:
    """Thin requests wrapper with automatic bearer auth + API base URL.

    The token is resolved at construction (`resolve_bearer_token`), so a job
    without credentials exits before it does any work. Raises HTTPError on
    non-2xx responses only when the caller calls raise_for_status().
    """

    def __init__(
        self,
        scopes: Optional[list[str]] = None,
        base: Optional[str] = None,
        timeout: float = 60.0,
    ):
        self.base = resolve_api_base(base)
        self.token = resolve_bearer_token(scopes or ["claims:read"], self.base)
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


if __name__ == "__main__":
    # Prints a client_credentials token for the scopes named on the command
    # line, for scripts that read EPIGRAPH_TOKEN. Never from EPIGRAPH_TOKEN
    # itself: that would only echo it back.
    _scopes = sys.argv[1:] or ["claims:read"]
    _id, _secret = _env("EPIGRAPH_SERVICE_CLIENT_ID"), _env("EPIGRAPH_SERVICE_SECRET")
    if not (_id and _secret):
        raise SystemExit("Set EPIGRAPH_SERVICE_CLIENT_ID and EPIGRAPH_SERVICE_SECRET.")
    _url = _env("EPIGRAPH_OAUTH_TOKEN_URL") or f"{resolve_api_base()}/oauth/token"
    print(fetch_service_token(_id, _secret, _url, _scopes))
