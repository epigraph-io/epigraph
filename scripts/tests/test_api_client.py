"""scripts/_api_client.py gets its bearer token from OAuth, never by self-minting.

Backlog 3e927af3: the helper used to sign its own HS256 JWT from
EPIGRAPH_JWT_SECRET (falling back to the committed development secret), with
caller-chosen scopes and agent_id and a hard-coded `sub`. Any script holding the
server's signing secret was a universal principal that bypassed the per-client
scope grants. The client now uses EPIGRAPH_TOKEN as given, or exchanges
EPIGRAPH_SERVICE_CLIENT_ID / EPIGRAPH_SERVICE_SECRET at the token endpoint with
the client_credentials grant (as decompose_claims does), and refuses otherwise.

Every test drives `EpiGraphClient` against a real HTTP server on 127.0.0.1 that
records each request, standing in for both the token endpoint and the API.
"""
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import _api_client  # noqa: E402

SECRET = "service-secret-do-not-echo-7f3a"
AUTH_ENV = (
    "EPIGRAPH_TOKEN",
    "EPIGRAPH_SERVICE_CLIENT_ID",
    "EPIGRAPH_SERVICE_SECRET",
    "EPIGRAPH_OAUTH_TOKEN_URL",
    "EPIGRAPH_API_BASE",
    "EPIGRAPH_JWT_SECRET",
    "EPIGRAPH_AGENT_ID",
    "EPIGRAPH_CLIENT_ID",
)


class _Server:
    """Records (method, path, headers, body) of every request. Token-endpoint
    paths answer `token_status` / `token_body`; every other path answers 200."""

    def __init__(self):
        self.requests = []
        self.token_paths = {"/oauth/token"}
        self.token_status = 200
        self.token_body = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                outer.requests.append((self.command, self.path, dict(self.headers), body))
                if self.path in outer.token_paths:
                    status, payload = outer.token_status, outer.token_body
                else:
                    status, payload = 200, {"ok": True}
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _handle

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def token_requests(self):
        return [r for r in self.requests if r[1] in self.token_paths]

    def api_requests(self):
        return [r for r in self.requests if r[1] not in self.token_paths]


@pytest.fixture
def server(monkeypatch):
    for name in AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    s = _Server()
    monkeypatch.setenv("EPIGRAPH_API_BASE", s.base)
    # As a deployment of the self-minting helper had it. The OAuth paths ignore
    # it (the token endpoint derives agent_id from the client), and setting it
    # keeps the old helper out of its missing-agent refusal, so each test meets
    # the old code on the path it is about.
    monkeypatch.setenv("EPIGRAPH_AGENT_ID", "00000000-0000-4000-8000-000000000001")
    yield s
    s.httpd.shutdown()
    s.httpd.server_close()


def _service_credentials(monkeypatch):
    monkeypatch.setenv("EPIGRAPH_SERVICE_CLIENT_ID", "svc-client")
    monkeypatch.setenv("EPIGRAPH_SERVICE_SECRET", SECRET)


def _exit_message(excinfo):
    return str(excinfo.value.code)


def test_a_signing_secret_alone_is_refused_not_used_to_mint(server, monkeypatch):
    """The old path: the server's HS256 secret and an agent id, no OAuth
    material. That used to yield a working self-signed token."""
    monkeypatch.setenv("EPIGRAPH_JWT_SECRET", "x" * 48)
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:read"])
    msg = _exit_message(e)
    assert "EPIGRAPH_TOKEN" in msg and "EPIGRAPH_SERVICE_CLIENT_ID" in msg, msg
    assert server.requests == []


def test_service_credentials_are_exchanged_with_client_credentials(server, monkeypatch):
    _service_credentials(monkeypatch)
    server.token_body = {
        "access_token": "issued-by-server",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "claims:read claims:write",
    }
    client = _api_client.EpiGraphClient(scopes=["claims:read", "claims:write"])
    assert client.get("/api/v1/probe").status_code == 200

    [(method, _path, headers, body)] = server.token_requests()
    assert method == "POST"
    assert headers["Content-Type"].startswith("application/x-www-form-urlencoded")
    assert urllib.parse.parse_qs(body) == {
        "grant_type": ["client_credentials"],
        "client_id": ["svc-client"],
        "client_secret": [SECRET],
        "scope": ["claims:read claims:write"],
    }
    [(_, path, api_headers, _)] = server.api_requests()
    assert path == "/api/v1/probe"
    assert api_headers["Authorization"] == "Bearer issued-by-server"


def test_the_token_url_can_be_overridden(server, monkeypatch):
    _service_credentials(monkeypatch)
    server.token_paths = {"/custom/token"}
    server.token_body = {"access_token": "t2", "scope": "claims:read"}
    monkeypatch.setenv("EPIGRAPH_OAUTH_TOKEN_URL", server.base + "/custom/token")
    client = _api_client.EpiGraphClient(scopes=["claims:read"])
    assert client.token == "t2"
    assert [r[1] for r in server.requests] == ["/custom/token"]


def test_an_explicit_token_is_used_verbatim_without_an_exchange(server, monkeypatch):
    _service_credentials(monkeypatch)
    monkeypatch.setenv("EPIGRAPH_TOKEN", "operator-supplied")
    client = _api_client.EpiGraphClient(scopes=["claims:write"])
    client.post("/api/v1/probe", json={})
    assert server.token_requests() == []
    [(_, _, headers, _)] = server.api_requests()
    assert headers["Authorization"] == "Bearer operator-supplied"


def test_a_refused_exchange_exits_without_echoing_the_secret(server, monkeypatch):
    _service_credentials(monkeypatch)
    server.token_status = 401
    server.token_body = {"error": "invalid_client"}
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:read"])
    msg = _exit_message(e)
    assert "401" in msg, msg
    assert SECRET not in msg


def test_a_response_without_an_access_token_exits(server, monkeypatch):
    _service_credentials(monkeypatch)
    server.token_body = {"token_type": "Bearer", "scope": "claims:read"}
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:read"])
    assert "access_token" in _exit_message(e)


def test_a_scope_the_client_was_not_granted_fails_at_construction(server, monkeypatch):
    """The token endpoint intersects the request with the client's grants and
    drops the rest silently; a job asking for claims:admin must stop here, not
    403 halfway through a run."""
    _service_credentials(monkeypatch)
    server.token_body = {"access_token": "narrow", "scope": "claims:write"}
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:write", "claims:admin"])
    msg = _exit_message(e)
    assert "claims:admin" in msg and SECRET not in msg, msg
