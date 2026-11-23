"""scripts/_api_client.py gets its bearer token from OAuth, never by self-minting.

Backlog 3e927af3: the helper used to sign its own HS256 JWT from
EPIGRAPH_JWT_SECRET (falling back to the committed development secret), with
caller-chosen scopes and agent_id and a hard-coded `sub`. Any script holding the
server's signing secret was a universal principal that bypassed the per-client
scope grants. The client now uses EPIGRAPH_TOKEN as given, or exchanges
EPIGRAPH_SERVICE_CLIENT_ID / EPIGRAPH_SERVICE_SECRET at the token endpoint with
the client_credentials grant (as decompose_claims does), and refuses otherwise.

Backlog 9265d519: a token supplied through EPIGRAPH_TOKEN used to be taken as
given, so an under-scoped, expired or revoked one failed on its first refused
call, partway through a run. The client now asks the API's /oauth/introspect
about it at construction and exits when it is not active or lacks a scope the
job requests.

Every test drives `EpiGraphClient` against a real HTTP server on 127.0.0.1 that
records each request, standing in for the token endpoint, the introspection
endpoint and the API.
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
OPERATOR_TOKEN = "operator-token-do-not-echo-91b2"
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
    paths answer `token_status` / `token_body`, the introspection path answers
    `introspect_status` / `introspect_body` (inactive unless a test says
    otherwise), and every other path answers 200."""

    def __init__(self):
        self.requests = []
        self.token_paths = {"/oauth/token"}
        self.token_status = 200
        self.token_body = {}
        self.introspect_path = "/oauth/introspect"
        self.introspect_status = 200
        self.introspect_body = {"active": False}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                outer.requests.append((self.command, self.path, dict(self.headers), body))
                if self.path in outer.token_paths:
                    status, payload = outer.token_status, outer.token_body
                elif self.path == outer.introspect_path:
                    status, payload = outer.introspect_status, outer.introspect_body
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

    def introspect_requests(self):
        return [r for r in self.requests if r[1] == self.introspect_path]

    def api_requests(self):
        return [
            r
            for r in self.requests
            if r[1] not in self.token_paths and r[1] != self.introspect_path
        ]


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
    # The exchange checks its own granted scopes; no introspection call.
    assert [r[1] for r in server.requests] == ["/custom/token"]


def test_an_explicit_token_is_used_verbatim_without_an_exchange(server, monkeypatch):
    _service_credentials(monkeypatch)
    monkeypatch.setenv("EPIGRAPH_TOKEN", OPERATOR_TOKEN)
    server.introspect_body = {"active": True, "scope": "claims:read claims:write"}
    client = _api_client.EpiGraphClient(scopes=["claims:write"])
    client.post("/api/v1/probe", json={})
    assert server.token_requests() == []
    [(_, _, headers, _)] = server.api_requests()
    assert headers["Authorization"] == f"Bearer {OPERATOR_TOKEN}"


def test_an_explicit_token_is_introspected_at_the_api_as_json(server, monkeypatch):
    """The server's `/oauth/introspect` takes a JSON `{"token": ...}` body (an
    axum `Json` extractor): a form-encoded RFC 7662 body would be refused by
    the real endpoint, so the request shape is pinned here."""
    monkeypatch.setenv("EPIGRAPH_TOKEN", OPERATOR_TOKEN)
    server.introspect_body = {"active": True, "scope": "claims:write"}
    _api_client.EpiGraphClient(scopes=["claims:write"])
    [(method, _path, headers, body)] = server.introspect_requests()
    assert method == "POST"
    assert headers["Content-Type"].startswith("application/json")
    assert json.loads(body) == {"token": OPERATOR_TOKEN}
    assert "Authorization" not in headers


def test_an_explicit_token_missing_a_scope_fails_at_construction(server, monkeypatch):
    """The token works for claims:write but the job also needs claims:admin:
    it must stop at construction, naming the scope, not 403 halfway through a
    run. The token itself stays out of the message."""
    monkeypatch.setenv("EPIGRAPH_TOKEN", OPERATOR_TOKEN)
    server.introspect_body = {"active": True, "scope": "claims:read claims:write"}
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:write", "claims:admin"])
    msg = _exit_message(e)
    assert "claims:admin" in msg and "EPIGRAPH_TOKEN" in msg, msg
    assert OPERATOR_TOKEN not in msg
    assert server.api_requests() == []


def test_an_inactive_explicit_token_fails_at_construction(server, monkeypatch):
    """Expired, revoked or signed by another key: introspection answers only
    `active: false`, and the client exits rather than run on it."""
    monkeypatch.setenv("EPIGRAPH_TOKEN", OPERATOR_TOKEN)
    server.introspect_body = {"active": False}
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:read"])
    msg = _exit_message(e)
    assert "not active" in msg, msg
    assert OPERATOR_TOKEN not in msg


def test_an_active_flag_that_is_not_true_is_not_active(server, monkeypatch):
    """Only a JSON `true` is active: a body without the flag, or with a
    truthy non-boolean, is refused like an inactive token."""
    monkeypatch.setenv("EPIGRAPH_TOKEN", OPERATOR_TOKEN)
    for body in ({"scope": "claims:read"}, {"active": "true", "scope": "claims:read"}):
        server.introspect_body = body
        with pytest.raises(SystemExit) as e:
            _api_client.EpiGraphClient(scopes=["claims:read"])
        assert "not active" in _exit_message(e), body


def test_an_unanswered_introspection_fails_closed(server, monkeypatch):
    """A 503 (the server's revocation lookup could not answer) is not a pass."""
    monkeypatch.setenv("EPIGRAPH_TOKEN", OPERATOR_TOKEN)
    server.introspect_status = 503
    server.introspect_body = {"error": "service unavailable"}
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:read"])
    msg = _exit_message(e)
    assert "503" in msg and "/oauth/introspect" in msg, msg
    assert OPERATOR_TOKEN not in msg


def test_an_unreachable_introspection_fails_closed(server, monkeypatch):
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
    monkeypatch.setenv("EPIGRAPH_API_BASE", f"http://127.0.0.1:{closed_port}")
    monkeypatch.setenv("EPIGRAPH_TOKEN", OPERATOR_TOKEN)
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:read"])
    msg = _exit_message(e)
    assert "unreachable" in msg, msg
    assert OPERATOR_TOKEN not in msg


def test_an_elevated_token_holds_admin_scopes_through_platform_admin(server, monkeypatch):
    """The server's `has_scope`: an elevated token carrying platform:admin
    holds the non-write admin scopes (claims:admin, groups:admin, ...) without
    carrying them. The check must not refuse a token the server would accept;
    it still refuses a :write scope the token does not carry."""
    monkeypatch.setenv("EPIGRAPH_TOKEN", OPERATOR_TOKEN)
    server.introspect_body = {"active": True, "scope": "claims:write platform:admin"}
    client = _api_client.EpiGraphClient(scopes=["claims:write", "claims:admin"])
    assert client.token == OPERATOR_TOKEN
    with pytest.raises(SystemExit) as e:
        _api_client.EpiGraphClient(scopes=["claims:write", "entity-types:write"])
    assert "entity-types:write" in _exit_message(e)


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
