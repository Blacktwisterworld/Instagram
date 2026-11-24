import os
import threading
from functools import lru_cache

import apsw

from vfs import HTTPRangeVFS

DB_URL = os.environ.get("DB_URL", "").strip()
HF_TOKEN = os.environ.get("HF_TOKEN", "").strip() or None

ALLOWED_FIELDS = {"id", "username", "email", "phone", "name"}

_vfs = None
_conn = None
_conn_lock = threading.Lock()


def _init_vfs_once():
    global _vfs
    if _vfs is None:
        _vfs = HTTPRangeVFS("httpvfs", token=HF_TOKEN)


def get_conn():
    global _conn
    if not DB_URL:
        raise RuntimeError("DB_URL env var is not set")
    with _conn_lock:
        if _conn is None:
            _init_vfs_once()
            _conn = apsw.Connection(
                DB_URL,
                flags=apsw.SQLITE_OPEN_READONLY,
                vfs="httpvfs",
            )
            _conn.execute("PRAGMA query_only = ON;")
        return _conn


def _row_to_dict(cursor_desc, row):
    return {col[0]: row[i] for i, col in enumerate(cursor_desc)}


def do_search(q: str, field: str, limit: int):
    conn = get_conn()
    q = q.strip()
    if not q:
        return []

    limit = max(1, min(int(limit), 100))

    if field == "any":
        # try indexed fields one by one (fast on index)
        for f in ("phone", "email", "username", "id"):
            rows = _run(conn, f, q, limit)
            if rows:
                return rows
        return []
    if field not in ALLOWED_FIELDS:
        raise ValueError(f"Invalid field: {field}")
    return _run(conn, field, q, limit)


def _run(conn, field, q, limit):
    sql = f"SELECT id, username, email, phone, name, address FROM users WHERE {field} = ? LIMIT ?"
    cursor = conn.cursor()
    cursor.execute(sql, (q, limit))
    desc = cursor.getdescription()
    out = []
    for row in cursor:
        out.append({col[0]: row[i] for i, col in enumerate(desc)})
    return out


@lru_cache(maxsize=256)
def cached_search(q: str, field: str, limit: int):
    # Convert to hashable and back
    return tuple((r["id"], r["username"], r["email"], r["phone"], r["name"], r["address"]) for r in do_search(q, field, limit))


def search(q: str, field: str, limit: int):
    rows = cached_search(q, field, limit)
    return [
        {"id": r[0], "username": r[1], "email": r[2], "phone": r[3], "name": r[4], "address": r[5]}
        for r in rows
    ]
