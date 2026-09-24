import base64
from dataclasses import FrozenInstanceError
import json
import math
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from e05.core import (ReadOnlyAdapter, QueryPolicy, QueryRefused, _digest,
                      MAX_VALUE_BYTES, LIMITS)


class Hardening(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript("CREATE TABLE t(x); INSERT INTO t VALUES(1),(2),(3);")
        self.a = ReadOnlyAdapter(self.conn)
        self.addCleanup(self.a.close)

    def test_policy_exact_types(self):
        for bad in (True, 1.0, "2", None):
            with self.assertRaises(ValueError):
                QueryPolicy(max_rows=bad)
        for bad in (True, math.nan, math.inf, "1"):
            with self.assertRaises(ValueError):
                QueryPolicy(timeout_s=bad)

    def test_policy_result_budget(self):
        for bad in (True, 1023, 8388609, 1024.0):
            with self.assertRaises(ValueError):
                QueryPolicy(max_result_bytes=bad)

    def test_policy_immutable(self):
        p = QueryPolicy()
        with self.assertRaises(FrozenInstanceError):
            p.max_rows = 0

    def test_corrupt_policy_revalidated(self):
        p = QueryPolicy()
        object.__setattr__(p, "max_rows", -1)
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT 1", policy=p)

    def test_falsey_policy_not_defaulted(self):
        for p in (False, 0, {}, [], ""):
            with self.assertRaises(QueryRefused):
                self.a.query("SELECT 1", policy=p)

    def test_sql_limits(self):
        for sql in ("", "SELECT 1\0", "SELECT '\ud800'", "SELECT '" + "x" * 65536 + "'"):
            with self.assertRaises(QueryRefused):
                self.a.query(sql)

    def test_leading_comments(self):
        self.assertEqual(self.a.query("/* read */ -- one\n SELECT 2; -- end")["rows"], [[2]])

    def test_all_identifier_quotes(self):
        for quote in ('"?;:x"', '[?;:x]', chr(96) + '?;:x' + chr(96)):
            self.assertEqual(self.a.query("SELECT 2 AS " + quote)["columns"][0]["name"], "?;:x")

    def test_unterminated_lexemes(self):
        for sql in ("SELECT 'x", 'SELECT "x', "SELECT [x", "SELECT 1 /*"):
            with self.assertRaises(QueryRefused):
                self.a.query(sql)

    def test_write_cte_refused(self):
        with self.assertRaises(QueryRefused):
            self.a.query("WITH c AS (SELECT 4) DELETE FROM t")
        self.assertEqual(self.a.query("SELECT count(*) FROM t")["rows"], [[3]])

    def test_unknown_function_not_called(self):
        calls = []
        self.conn.create_function("external_effect", 0, lambda: calls.append(1) or 1)
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT external_effect()")
        self.assertEqual(calls, [])

    def test_extension_and_pragma_functions_refused(self):
        for sql in ("SELECT load_extension('absent')", "SELECT * FROM pragma_table_info('t')"):
            with self.assertRaises(QueryRefused):
                self.a.query(sql)

    def test_deny_attached_and_temp(self):
        conn = sqlite3.connect(":memory:")
        conn.executescript("ATTACH ':memory:' AS other; CREATE TABLE other.t(x); CREATE TEMP TABLE tmp(x);")
        with ReadOnlyAdapter(conn) as a:
            for sql in ("SELECT * FROM other.t", "SELECT * FROM tmp"):
                with self.assertRaises(QueryRefused):
                    a.query(sql)

    def test_authorizer_reinstalled(self):
        self.conn.set_authorizer(None)
        self.conn.create_function("external_effect", 0, lambda: 1)
        self.conn.execute("SELECT external_effect()").close()
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT external_effect()")

    def test_parameter_type_rejection(self):
        class Custom:
            def __conform__(self, protocol):
                raise AssertionError("must not adapt")
        for value in (True, 2**63, -(2**63)-1, Custom(), bytearray(b"x"), ["x"]):
            with self.assertRaises(QueryRefused):
                self.a.query("SELECT ?", (value,))

    def test_binding_shapes(self):
        self.assertEqual(self.a.query("SELECT :one + :two", {"one": 1, "two": 2})["rows"], [[3]])
        self.assertEqual(self.a.query("SELECT ?2, ?1", [1, 2])["rows"], [[2, 1]])
        for sql, params in (("SELECT ?", ()), ("SELECT ?", (1, 2)), ("SELECT :x", {"y": 1})):
            with self.assertRaises(QueryRefused):
                self.a.query(sql, params)

    def test_parameter_budgets(self):
        for params in ((1,) * 257, (b"x" * (MAX_VALUE_BYTES + 1),), ("é" * MAX_VALUE_BYTES,), (b"x" * MAX_VALUE_BYTES,) * 5):
            with self.assertRaises(QueryRefused):
                self.a.query("SELECT ?", params)

    def test_named_key_validation(self):
        for params in ({1: "x"}, {"é": 1}, {"bad key": 1}):
            with self.assertRaises(QueryRefused):
                self.a.query("SELECT 1", params)

    def test_engine_large_value_limit(self):
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT zeroblob(2000000000)")
        self.assertEqual(self.a.query("SELECT 1")["rows"], [[1]])

    def test_cell_limit(self):
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT zeroblob(262145)")

    def test_column_limit(self):
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT " + ",".join("1" for _ in range(129)))

    def test_byte_budget_refuses_no_partial(self):
        with self.assertRaisesRegex(QueryRefused, "byte budget"):
            self.a.query("SELECT hex(zeroblob(400)) FROM t", policy=QueryPolicy(max_result_bytes=1024))

    def test_schema_counts_toward_budget(self):
        with self.assertRaisesRegex(QueryRefused, "byte budget"):
            self.a.query('SELECT 1 AS "' + "a" * 1024 + '" WHERE 0', policy=QueryPolicy(max_result_bytes=1024))

    def test_truncation_exact_boundary(self):
        self.assertFalse(self.a.query("SELECT * FROM t", policy=QueryPolicy(max_rows=3))["truncated"])
        self.assertTrue(self.a.query("SELECT * FROM t", policy=QueryPolicy(max_rows=2))["truncated"])

    def test_blob_and_nonfinite_are_json(self):
        result = self.a.query("SELECT ?, ?, ?", (b"\0\xff", math.inf, -math.inf))
        json.dumps(result, allow_nan=False)
        self.assertEqual(base64.b64decode(result["rows"][0][0]["base64"]), b"\0\xff")
        self.assertEqual(result["rows"][0][1], {"type": "float", "value": "inf"})

    def test_nan_binding_becomes_null(self):
        result = self.a.query("SELECT ?", (math.nan,))
        self.assertEqual(result["rows"], [[None]])
        self.assertNotEqual(result["receipt"]["params_digest"], self.a.query("SELECT ?", (None,))["receipt"]["params_digest"])

    def test_type_tag_collision_regressions(self):
        values = (math.nan, "__nonfinite__:nan", math.inf, "__nonfinite__:inf",
                  b"x", "b'x'", 1, 1.0, None, "None", {"type": "blob", "base64": "eA=="})
        self.assertEqual(len({_digest(v) for v in values}), len(values))

    def test_mapping_and_sequence_hash_separation(self):
        self.assertNotEqual(_digest({"x": 1}), _digest([["x", 1]]))
        self.assertEqual(_digest({"x": 1, "y": 2}), _digest({"y": 2, "x": 1}))

    def test_columns_bound_to_result(self):
        a = self.a.query("SELECT 1 AS a")
        b = self.a.query("SELECT 1 AS b")
        self.assertNotEqual(a["receipt"]["result_digest"], b["receipt"]["result_digest"])
        self.assertEqual(a["receipt"]["result_digest"], _digest({"rows": a["rows"], "columns": a["columns"]}))

    def test_receipt_binds_policy_and_flags(self):
        result = self.a.query("SELECT * FROM t", policy=QueryPolicy(max_rows=1))
        receipt = result["receipt"]
        digest = receipt.pop("receipt_digest")
        self.assertEqual(digest, _digest(receipt))
        for key, value in (("truncated", False), ("policy", {}), ("file_mode_ro", True)):
            changed = dict(receipt, **{key: value})
            self.assertNotEqual(digest, _digest(changed))

    def test_duplicate_columns_and_empty_types(self):
        result = self.a.query("SELECT 1 AS same, NULL AS same WHERE 0")
        self.assertEqual([c["index"] for c in result["columns"]], [0, 1])
        self.assertEqual([c["observed_types"] for c in result["columns"]], [["unknown"], ["unknown"]])

    def test_limits_restored_after_failure(self):
        before = {k: self.conn.getlimit(k) for k in LIMITS}
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT * FROM absent")
        self.assertEqual(before, {k: self.conn.getlimit(k) for k in LIMITS})

    def test_stricter_existing_limit_preserved(self):
        self.conn.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 1)
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT 1,2")
        self.assertEqual(self.conn.getlimit(sqlite3.SQLITE_LIMIT_COLUMN), 1)

    def test_monotonic_not_wall_clock(self):
        with patch("e05.core.time.time", side_effect=AssertionError):
            self.assertEqual(self.a.query("SELECT 1")["rows"], [[1]])

    def test_timeout_cleanup(self):
        with self.assertRaisesRegex(QueryRefused, "time ceiling"):
            self.a.query("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT sum(x) FROM c", policy=QueryPolicy(timeout_s=0.1))
        self.assertEqual(self.a.query("SELECT 1")["rows"], [[1]])

    def test_factory_reset(self):
        self.conn.row_factory = lambda *args: (_ for _ in ()).throw(AssertionError())
        self.conn.text_factory = bytes
        self.assertEqual(self.a.query("SELECT 'abc'")["rows"], [["abc"]])

    def test_close_and_context(self):
        self.a.close()
        self.a.close()
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            self.conn.execute("SELECT 1")

    def test_fresh_file_readonly_and_escaped_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test # space.sqlite"
            conn = sqlite3.connect(path)
            conn.executescript("CREATE TABLE t(x); INSERT INTO t VALUES(7);")
            conn.close()
            with ReadOnlyAdapter.open_file(path) as a:
                self.assertEqual(a.query("SELECT * FROM t")["rows"], [[7]])
                self.assertTrue(a.query("SELECT 1")["receipt"]["file_mode_ro"])
                a._conn.set_authorizer(None)
                with self.assertRaises(sqlite3.OperationalError):
                    a._conn.execute("DELETE FROM t")

    def test_missing_file_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "absent.sqlite"
            with self.assertRaises(FileNotFoundError):
                ReadOnlyAdapter.open_file(path)
            self.assertFalse(path.exists())

    def test_locked_database_does_not_wait_busy_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "locked.sqlite"
            writer = sqlite3.connect(path)
            try:
                writer.execute("CREATE TABLE t(x)")
                with ReadOnlyAdapter.open_file(path) as a:
                    writer.execute("BEGIN EXCLUSIVE")
                    start = time.monotonic()
                    with self.assertRaises(QueryRefused):
                        a.query("SELECT * FROM t", policy=QueryPolicy(timeout_s=0.1))
                    self.assertLess(time.monotonic() - start, 1)
            finally:
                writer.close()
