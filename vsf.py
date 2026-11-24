"""
HTTP Range Request VFS for SQLite using apsw.
Reads a remote SQLite file (e.g. on Hugging Face) without full download.
"""
import threading
from collections import OrderedDict

import apsw
import requests


class HTTPRangeVFS(apsw.VFS):
    def __init__(self, vfsname="httpvfs", token=None):
        self.vfsname_ = vfsname
        self.token = token
        super().__init__(vfsname, base="")

    def xOpen(self, name, flags):
        filename = name[0] or name[1]
        return HTTPRangeFile(filename, self.vfsname_, self.token)


class HTTPRangeFile(apsw.VFSFile):
    PAGE_SIZE = 4096
    CACHE_MAX = 512  # ~2MB RAM cache

    def __init__(self, url, vfsname, token=None):
        self.url = url
        self.vfsname = vfsname
        self.token = token
        self.session = requests.Session()
        self.size = 0
        self.cache = OrderedDict()
        self.lock = threading.Lock()
        self._init_size()

    def _init_size(self):
        headers = self._headers()
        try:
            r = self.session.head(self.url, headers=headers, allow_redirects=True, timeout=30)
            if r.status_code >= 400:
                raise RuntimeError(f"HEAD {self.url} -> {r.status_code}")
            self.size = int(r.headers.get("Content-Length", 0))
        except Exception:
            self.size = 0

    def _headers(self):
        h = {}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    # ---------- Required VFS methods ----------
    def xRead(self, amount, offset):
        if self.size == 0 or offset >= self.size:
            return b""
        end = min(offset + amount, self.size) - 1
        key = (offset, amount)
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                return self.cache[key]
        headers = self._headers()
        headers["Range"] = f"bytes={offset}-{end}"
        try:
            r = self.session.get(self.url, headers=headers, allow_redirects=True, timeout=30)
            r.raise_for_status()
            data = r.content
        except Exception:
            return b""
        with self.lock:
            self.cache[key] = data
            if len(self.cache) > self.CACHE_MAX:
                self.cache.popitem(last=False)
        return data

    def xWrite(self, data, offset):
        raise apsw.ReadOnlyError()

    def xTruncate(self, newsize):
        raise apsw.ReadOnlyError()

    def xSync(self, flags):
        return None

    def xFileSize(self):
        return self.size

    def xLock(self, level):
        return None

    def xUnlock(self, level):
        return None

    def xCheckReservedLock(self):
        return False

    def xFileControl(self, op, ptr):
        return False

    def xSectorSize(self):
        return self.PAGE_SIZE

    def xDeviceCharacteristics(self):
        return apsw.SQLITE_IOCAP_IMMUTABLE | apsw.SQLITE_IOCAP_ATOMIC

    def xClose(self):
        try:
            self.session.close()
        except Exception:
            pass
