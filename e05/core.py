"""Bounded read queries over trusted SQLite databases and connections."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
import time

VERSION = "0.1.2a1"
MAX_SQL_BYTES = 65536
MAX_VALUE_BYTES = 262144
MAX_PARAMS_BYTES = 1048576
# All names are deny-by-default. A trusted caller can still override builtins.
FUNCTIONS = frozenset("""abs avg char coalesce count glob group_concat hex ifnull
instr length like likelihood likely lower ltrim max min nullif quote replace
round rtrim sign substr substring sum total trim typeof unicode unlikely upper
zeroblob row_number rank dense_rank percent_rank cume_dist ntile lag lead
first_value last_value nth_value""".split())
LIMITS = {
    sqlite3.SQLITE_LIMIT_LENGTH: 1048576,
    sqlite3.SQLITE_LIMIT_SQL_LENGTH: MAX_SQL_BYTES,
    sqlite3.SQLITE_LIMIT_COLUMN: 128,
    sqlite3.SQLITE_LIMIT_EXPR_DEPTH: 64,
    sqlite3.SQLITE_LIMIT_COMPOUND_SELECT: 64,
    sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER: 256,
    sqlite3.SQLITE_LIMIT_VDBE_OP: 250000,
    sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH: 4096,
}


class QueryRefused(Exception):
    """Invalid, unauthorized, failed or over-budget query; no partial result."""


def _json(obj):
    return json.dumps(obj, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":"))


def _canon(obj):
    """Type-separated hashing: SQL values cannot collide with tag-like strings."""
    kind = type(obj)
    if obj is None:
        return ["null"]
    if kind is bool:
        return ["bool", obj]
    if kind is int:
        return ["int", str(obj)]
    if kind is float:
        return ["float", obj.hex()]
    if kind is str:
        return ["str", obj]
    if kind is bytes:
        return ["bytes", base64.b64encode(obj).decode("ascii")]
    if kind in (tuple, list):
        return ["sequence", [_canon(v) for v in obj]]
    if kind is dict and all(type(k) is str for k in obj):
        return ["mapping", [[k, _canon(obj[k])] for k in sorted(obj)]]
    raise QueryRefused("unsupported value type")


def _digest(obj):
    return "sha256:" + hashlib.sha256(_json(_canon(obj)).encode()).hexdigest()


def _text_size(text):
    try:
        return len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise QueryRefused("text must be valid Unicode") from exc


def _native(value):
    if value is None:
        return 0
    if type(value) is int and -(2**63) <= value < 2**63:
        return 8
    if type(value) is float:
        return 8
    if type(value) in (str, bytes):
        size = _text_size(value) if type(value) is str else len(value)
        if size <= MAX_VALUE_BYTES:
            return size
    raise QueryRefused("value type, integer range or 256 KiB value budget refused")


def _parameters(params):
    if type(params) not in (tuple, list, dict) or len(params) > 256:
        raise QueryRefused("params must be an exact tuple/list/dict with at most 256 entries")
    if type(params) is dict:
        if any(type(k) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,127}", k)
               for k in params):
            raise QueryRefused("named binding keys must be simple ASCII identifiers")
        snapshot = dict(params)
        size = sum(len(k) + _native(v) for k, v in snapshot.items())
    else:
        snapshot = tuple(params)
        size = sum(_native(v) for v in snapshot)
    if size > MAX_PARAMS_BYTES:
        raise QueryRefused("parameter byte budget exceeded")
    return snapshot


def _strip_literals(sql):
    """Mask SQLite quoting/comments for the SELECT/CTE shape check only."""
    parts = []
    i = 0
    while i < len(sql):
        if sql.startswith("--", i):
            end = sql.find("\n", i + 2)
            i = len(sql) if end < 0 else end
            parts.append(" ")
        elif sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0:
                raise QueryRefused("unterminated SQL comment")
            i = end + 2
            parts.append(" ")
        elif sql[i] in ("'", '"', chr(96), "["):
            closing = "]" if sql[i] == "[" else sql[i]
            i += 1
            while i < len(sql):
                if sql[i] == closing:
                    i += 1
                    if closing != "]" and i < len(sql) and sql[i] == closing:
                        i += 1
                        continue
                    break
                i += 1
            else:
                raise QueryRefused("unterminated SQL quote")
            parts.append(" ")
        else:
            parts.append(sql[i])
            i += 1
    return "".join(parts)


@dataclass(frozen=True)
class QueryPolicy:
    max_rows: int = 1000
    timeout_s: float = 2.0
    max_result_bytes: int = 1048576

    def __post_init__(self):
        if type(self.max_rows) is not int or not 1 <= self.max_rows <= 10000:
            raise ValueError("max_rows must be an integer in 1..10000")
        if type(self.timeout_s) not in (int, float) or not math.isfinite(self.timeout_s) or not 0.1 <= self.timeout_s <= 30:
            raise ValueError("timeout_s must be finite in 0.1..30")
        if type(self.max_result_bytes) is not int or not 1024 <= self.max_result_bytes <= 8388608:
            raise ValueError("max_result_bytes must be an integer in 1024..8388608")


def _wire(value):
    _native(value)
    if type(value) is bytes:
        return {"type": "blob", "base64": base64.b64encode(value).decode("ascii")}
    if type(value) is float and not math.isfinite(value):
        return {"type": "float", "value": value.hex()}
    return value


class ReadOnlyAdapter:
    """Own a dedicated trusted connection until close(); never share it externally.

    SQL writes are denied. This is not an OS sandbox, data authorization service,
    or protection against a malicious database, extension, callback or caller.
    Prefer open_file() for a fresh connection with SQLite mode=ro.
    """

    def __init__(self, conn: sqlite3.Connection):
        if type(conn) is not sqlite3.Connection:
            raise TypeError("an exact sqlite3.Connection is required")
        if not hasattr(conn, "setlimit"):
            raise RuntimeError("Python 3.11+ with sqlite3 runtime limits is required")
        self._conn = conn
        self._lock = threading.RLock()
        self._closed = False
        self._file_mode_ro = False
        conn.row_factory = None
        conn.text_factory = str
        # We take over these connection settings; no prior callback can be read back.
        conn.set_authorizer(None)
        conn.execute("PRAGMA busy_timeout=0").close()
        try:
            conn.enable_load_extension(False)
        except (AttributeError, sqlite3.NotSupportedError):
            pass
        conn.set_authorizer(self._authorize)

    @classmethod
    def open_file(cls, path):
        """Open an existing trusted local file with mode=ro; never create a DB."""
        resolved = Path(path).resolve(strict=True)
        if not resolved.is_file():
            raise ValueError("database path must name a file")
        conn = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True,
                               timeout=0, detect_types=0, cached_statements=0)
        try:
            adapter = cls(conn)
        except BaseException:
            conn.close()
            raise
        adapter._file_mode_ro = True
        return adapter

    @staticmethod
    def _authorize(action, arg1, arg2, dbname, source):
        if action == sqlite3.SQLITE_FUNCTION:
            return sqlite3.SQLITE_OK if arg2 and arg2.lower() in FUNCTIONS else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_READ:
            return sqlite3.SQLITE_OK if dbname in ("main", None) else sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_RECURSIVE) else sqlite3.SQLITE_DENY

    def close(self):
        with self._lock:
            if not self._closed:
                self._conn.close()
                self._closed = True

    def __enter__(self):
        if self._closed:
            raise QueryRefused("adapter is closed")
        return self

    def __exit__(self, *exc):
        self.close()

    def query(self, sql, params=(), policy=None):
        if policy is None:
            policy = QueryPolicy()
        if type(policy) is not QueryPolicy:
            raise QueryRefused("policy must be a QueryPolicy")
        try:
            policy.__post_init__()
        except (ValueError, TypeError) as exc:
            raise QueryRefused("invalid query policy") from exc
        if type(sql) is not str or not 1 <= _text_size(sql) <= MAX_SQL_BYTES or "\0" in sql:
            raise QueryRefused("sql must be nonempty Unicode, NUL-free, at most 64 KiB")
        stripped = _strip_literals(sql)
        if not re.match(r"^\s*(select|with)\b", stripped, re.I):
            raise QueryRefused("only SELECT or WITH queries are accepted")
        if ";" in stripped.rstrip().removesuffix(";"):
            raise QueryRefused("multi-statement queries are refused")
        params = _parameters(params)
        with self._lock:
            if self._closed:
                raise QueryRefused("adapter is closed")
            return self._query(sql, params, policy)

    def _query(self, sql, params, policy):
        started = time.monotonic()
        deadline = started + policy.timeout_s
        saved_limits = {}
        cur = None
        rows = []
        truncated = False
        try:
            # Reinstall for each execution; this also invalidates cached authorization.
            self._conn.set_authorizer(self._authorize)
            self._conn.row_factory = None
            self._conn.text_factory = str
            for category, ceiling in LIMITS.items():
                previous = self._conn.getlimit(category)
                saved_limits[category] = previous
                self._conn.setlimit(category, min(previous, ceiling))
            self._conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            cur = self._conn.cursor()
            cur.execute(sql, params)  # SQLite parses bindings and enforces one statement.
            names = [d[0] for d in cur.description]
            kinds = [set() for _ in names]
            used = len(_json(names).encode())
            while True:
                if time.monotonic() >= deadline:
                    raise QueryRefused("query exceeded the time ceiling")
                row = cur.fetchone()
                if row is None:
                    break
                if len(rows) == policy.max_rows:
                    truncated = True
                    break
                converted = [_wire(v) for v in row]
                used += len(_json(converted).encode())
                if used > policy.max_result_bytes:
                    raise QueryRefused("result byte budget exceeded")
                for i, value in enumerate(row):
                    if value is not None:
                        kinds[i].add(type(value).__name__)
                rows.append(converted)
            columns = [{"name": name, "index": i, "observed_types": sorted(kinds[i]) or ["unknown"]}
                       for i, name in enumerate(names)]
            result = {"columns": columns, "rows": rows}
            # Exact compact JSON byte size for columns + retained rows.
            if len(_json(result).encode()) > policy.max_result_bytes:
                raise QueryRefused("result byte budget exceeded")
            receipt = {
                "schema": "e05/query-receipt/v2", "adapter_version": VERSION,
                "sqlite_version": sqlite3.sqlite_version,
                "sql_digest": _digest(sql), "params_digest": _digest(params),
                "policy": asdict(policy), "row_count": len(rows), "truncated": truncated,
                "duration_s": round(time.monotonic() - started, 6),
                "result_digest": _digest(result),
                "read_only_scope": "sqlite-authorizer-main",
                "file_mode_ro": self._file_mode_ro,
            }
            if time.monotonic() >= deadline:
                raise QueryRefused("query exceeded the time ceiling")
            receipt["receipt_digest"] = _digest(receipt)
            return {**result, "truncated": truncated, "receipt": receipt, "read_only": True}
        except (sqlite3.Error, OverflowError, UnicodeError, MemoryError) as exc:
            if time.monotonic() >= deadline or "interrupted" in str(exc).lower():
                raise QueryRefused("query exceeded the time ceiling") from exc
            raise QueryRefused("SQLite refused or failed the query") from exc
        finally:
            if cur is not None:
                cur.close()
            self._conn.set_progress_handler(None, 0)
            for category, previous in saved_limits.items():
                self._conn.setlimit(category, previous)
