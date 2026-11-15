"""In-memory stand-in for `GET /api/v1/claims/by-labels`, shared by the
backlog-label script tests.

It honours the route's paging contract (crates/epigraph-api/src/routes/claims.rs,
`list_by_labels`, and `LabelCursor` in crates/epigraph-db/src/repos/claim.rs):
rows ordered `(created_at DESC, id DESC)`, `limit` clamped to 100, `offset`
skips rows, `after` resumes strictly after the cursor's POSITION (rows whose
`(created_at, id)` sorts below it), the two cannot be combined (400), and a
full page carries an `X-Next-Cursor` response header while a short page
carries none. The cursor is the route's token, `k1.<created_at micros>.<id
hex>`. Because it names a position, not a row, it stays valid when the row it
was cut from leaves the result set.

`insert_after_first_page` simulates a concurrent write: once the first page has
been served, a newer row lands at the head of the order. Offset paging then
re-reads the last row of page one; keyset paging does not.

`after_first_page` is a hook run on the row list once the first page has been
served, for any other concurrent change (for example a row that stops matching
the filter).
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


def newer_row(prefix: str = "n") -> dict:
    """One row created after every row of `make_rows`, so it sorts first."""
    row = make_rows(1, prefix=prefix)[0]
    row["created_at"] = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc).isoformat()
    return row


def _key(row: dict) -> tuple[int, str]:
    """A row's `(created_at micros, id hex)` sort position."""
    created = datetime.datetime.fromisoformat(row["created_at"])
    micros = (created - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(
        microseconds=1
    )
    return (micros, row["id"].replace("-", "").lower())


def cursor_of(row: dict) -> str:
    """The route's next-page token for `row`: `k1.<created_at micros>.<id hex>`."""
    micros, id_hex = _key(row)
    return f"k1.{micros}.{id_hex}"


def _decode(token: str) -> tuple[int, str] | None:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "k1":
        return None
    try:
        micros = int(parts[1])
    except ValueError:
        return None
    id_hex = parts[2].lower()
    if len(id_hex) != 32 or any(c not in "0123456789abcdef" for c in id_hex):
        return None
    return (micros, id_hex)


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

    def __init__(
        self,
        rows: list[dict],
        insert_after_first_page: dict | None = None,
        after_first_page=None,
    ):
        self.rows = sorted(rows, key=_key, reverse=True)
        self._pending_insert = insert_after_first_page
        self._after_first_page = after_first_page
        self._served_first = False
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
            pos = _decode(after)
            if pos is None:
                return Resp({"error": "malformed after cursor"}, status=400)
            # `(created_at, id) < cursor`, like the route's keyset predicate.
            candidates = [r for r in self.rows if _key(r) < pos]
        else:
            candidates = self.rows[offset:]
        page = candidates[:limit]
        hdrs = {}
        if len(page) == limit:
            hdrs["X-Next-Cursor"] = cursor_of(page[-1])
        if not self._served_first:
            self._served_first = True
            if self._pending_insert is not None:
                self.rows.append(self._pending_insert)
            if self._after_first_page is not None:
                self._after_first_page(self.rows)
            self.rows.sort(key=_key, reverse=True)
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
        return Resp(self.rows, {"X-Next-Cursor": cursor_of(self.rows[-1])})
