"""In-memory stand-in for `GET /api/v1/claims/by-labels`, shared by the
backlog-label script tests.

It honours the route's paging contract (crates/epigraph-api/src/routes/claims.rs,
`list_by_labels`): rows ordered `(created_at DESC, id DESC)`, `limit` clamped to
100, `offset` skips rows, `after` resumes strictly after the cursor's row, the
two cannot be combined (400), and a full page carries an `X-Next-Cursor`
response header while a short page carries none.

`insert_after_first_page` simulates a concurrent write: once the first page has
been served, a newer row lands at the head of the order. Offset paging then
re-reads the last row of page one; keyset paging does not.
"""
import datetime

import httpx

MAX_PAGE_LIMIT = 100


def make_rows(n: int, prefix: str = "c") -> list[dict]:
    """`n` rows, newest first, with distinct created_at and ids."""
    base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    rows = []
    for i in range(n):
        created = base + datetime.timedelta(seconds=n - i)
        rows.append(
            {
                "id": f"{prefix}{i:07d}-0000-4000-8000-000000000000",
                "content": f"row {i}",
                "created_at": created.isoformat(),
                "is_current": True,
                "supersedes": None,
            }
        )
    return rows


class Resp:
    def __init__(self, payload, headers=None, status=200):
        self._payload = payload
        self.status_code = status
        # httpx.Headers is case-insensitive, like the real response.
        self.headers = httpx.Headers(headers or {})

    def raise_for_status(self):
        if self.status_code >= 400:
            req = httpx.Request("GET", "http://fake/api/v1/claims/by-labels")
            raise httpx.HTTPStatusError(
                f"{self.status_code}", request=req, response=httpx.Response(self.status_code, request=req)
            )

    def json(self):
        return self._payload


class KeysetServer:
    """Serves one label query's rows under the route's paging contract."""

    def __init__(self, rows: list[dict], insert_after_first_page: dict | None = None):
        self.rows = list(rows)
        self._pending_insert = insert_after_first_page
        self.calls: list[dict] = []

    def get(self, url, params=None, headers=None, timeout=None):
        params = dict(params or {})
        self.calls.append(params)
        limit = max(1, min(int(params.get("limit", 20)), MAX_PAGE_LIMIT))
        offset = max(0, int(params.get("offset", 0) or 0))
        after = (params.get("after") or "").strip()
        if after and offset:
            return Resp({"error": "after and offset cannot be combined"}, status=400)
        if after:
            ids = [r["id"] for r in self.rows]
            if not after.startswith("k1.") or after[3:] not in ids:
                return Resp({"error": "malformed after cursor"}, status=400)
            start = ids.index(after[3:]) + 1
        else:
            start = offset
        page = self.rows[start : start + limit]
        hdrs = {}
        if len(page) == limit:
            hdrs["X-Next-Cursor"] = "k1." + page[-1]["id"]
        if self._pending_insert is not None:
            self.rows.insert(0, self._pending_insert)
            self._pending_insert = None
        return Resp(page, hdrs)


class LegacyServer:
    """A server that predates keyset paging: ignores `after`, never sends the header."""

    def __init__(self, rows: list[dict]):
        self.rows = list(rows)

    def get(self, url, params=None, headers=None, timeout=None):
        params = dict(params or {})
        limit = max(1, min(int(params.get("limit", 20)), MAX_PAGE_LIMIT))
        offset = max(0, int(params.get("offset", 0) or 0))
        return Resp(self.rows[offset : offset + limit])


class StuckCursorServer:
    """Always returns a full page with the same cursor (a server-side paging bug)."""

    def __init__(self):
        self.rows = make_rows(MAX_PAGE_LIMIT, prefix="s")
        self.calls = 0

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls += 1
        return Resp(self.rows, {"X-Next-Cursor": "k1." + self.rows[-1]["id"]})
