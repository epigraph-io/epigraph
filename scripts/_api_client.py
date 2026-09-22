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
    EPIGRAPH_CLIENT_ID      oauth_clients.id used as the JWT `sub`
    EPIGRAPH_AGENT_ID       agents.id used as the JWT `agent_id` claim

EPIGRAPH_AGENT_ID is new and it matters. Every route that returns claim
content moved behind Bearer auth, and the `Viewer` a read path derives is
resolved FROM `agent_id` — a token whose `agent_id` claim is null is
structurally deficient and is refused with 401 `invalid_token`, not 403. Set
EPIGRAPH_AGENT_ID to the `agents.id` the script should act as, or pass
`agent_id=` explicitly.

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
# provenance_log.principal_id has an FK to oauth_clients(id), so the JWT
# `sub` (= auth.client_id = recorded principal_id) must be a real client row.
# Default to the existing `epigraph-admin` service client (has claims:admin
# + all needed scopes granted). Override via EPIGRAPH_CLIENT_ID env var.
DEFAULT_CLIENT_ID = "5997f752-5d79-48bc-b876-cb77498066a6"
# There is deliberately no DEFAULT_AGENT_ID. `sub` can have a sensible default
# because it names a *client* row that exists in every deployment; `agent_id`
# names the PRINCIPAL whose group membership decides what the token can read,
# and defaulting that to somebody would hand every script one identity's view
# of the corpus by accident.


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

    `sub` defaults to the epigraph-admin oauth_clients row (via
    EPIGRAPH_CLIENT_ID env var or DEFAULT_CLIENT_ID) so the provenance FK
    is satisfied. A random `sub` would 500 on every write.

    `agent_id` falls back to EPIGRAPH_AGENT_ID. The claim was always emitted
    here, but no caller ever supplied a value, so it was always null — which is
    exactly the token shape the API now refuses on every read path. There is no
    hardcoded default: an unset EPIGRAPH_AGENT_ID yields a null claim, and the
    401 that follows is the correct, legible outcome.
    """
    secret = os.environ.get("EPIGRAPH_JWT_SECRET", DEFAULT_JWT_SECRET)
    if client_id is None:
        client_id = uuid.UUID(os.environ.get("EPIGRAPH_CLIENT_ID", DEFAULT_CLIENT_ID))
    if agent_id is None:
        env_agent_id = os.environ.get("EPIGRAPH_AGENT_ID")
        if env_agent_id:
            agent_id = uuid.UUID(env_agent_id)
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": str(client_id),
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
        agent_id: Optional[uuid.UUID] = None,
    ):
        self.base = (base or os.environ.get("EPIGRAPH_API_BASE", DEFAULT_API_BASE)).rstrip("/")
        # agent_id threads through to the JWT `agent_id` claim; when None it
        # falls back to EPIGRAPH_AGENT_ID.
        #
        # Fail here rather than at the first request. mint_bearer_token is a raw
        # token helper and will happily emit a null `agent_id` claim -- a caller
        # exercising the 401 path is a legitimate use of it. EpiGraphClient is
        # not that: its callers are batch jobs
        # (anchor_papers_to_themes.py, classify_paper_document_type.py,
        # update_theme_workflow_steps.py, lib/nli_stance.py) that would
        # otherwise run their setup, issue a request, and die on an opaque 401
        # whose cause is an unset environment variable several files away.
        if agent_id is None:
            env_agent_id = os.environ.get("EPIGRAPH_AGENT_ID")
            if not env_agent_id:
                raise SystemExit(
                    "EPIGRAPH_AGENT_ID is not set.\n"
                    "Since the PR-03 router inversion, a token whose `agent_id` claim is\n"
                    "null is refused 401 invalid_token on every route this client uses.\n"
                    "Set EPIGRAPH_AGENT_ID to the agents.id this job should act as, or\n"
                    "pass agent_id= explicitly. There is deliberately no default: agent_id\n"
                    "names the principal whose group membership decides what the token can\n"
                    "read."
                )
            agent_id = uuid.UUID(env_agent_id)
        self.token = mint_bearer_token(scopes or ["claims:read"], agent_id=agent_id)
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
