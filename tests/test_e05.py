import sqlite3
import unittest

from e05.core import QueryPolicy, QueryRefused, ReadOnlyAdapter


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE users(id INTEGER, name TEXT, balance REAL);
        INSERT INTO users VALUES (1,'alice',10.5),(2,'bob',3.0),(3,'cara',7.25);
    """)
    return conn


class Policies(unittest.TestCase):
    def test_bounds(self):
        with self.assertRaises(ValueError):
            QueryPolicy(max_rows=0)
        with self.assertRaises(ValueError):
            QueryPolicy(timeout_s=0)


class Queries(unittest.TestCase):
    def setUp(self):
        self.a = ReadOnlyAdapter(make_db())
        self.addCleanup(self.a.close)

    def test_select_with_bound_params(self):
        res = self.a.query("SELECT name, balance FROM users WHERE id = ?", (2,))
        self.assertEqual(res["rows"], [["bob", 3.0]])
        self.assertEqual([c["name"] for c in res["columns"]],
                         ["name", "balance"])
        self.assertIn("float", res["columns"][1]["observed_types"])
        self.assertTrue(res["read_only"])

    def test_cte_allowed(self):
        res = self.a.query("WITH t AS (SELECT id FROM users) "
                           "SELECT count(*) FROM t")
        self.assertEqual(res["rows"], [[3]])

    def test_receipt_digests_and_determinism(self):
        r1 = self.a.query("SELECT id FROM users ORDER BY id")
        r2 = self.a.query("SELECT id FROM users ORDER BY id")
        self.assertEqual(r1["receipt"]["sql_digest"], r2["receipt"]["sql_digest"])
        self.assertEqual(r1["receipt"]["result_digest"],
                         r2["receipt"]["result_digest"])
        self.assertEqual(r1["receipt"]["row_count"], 3)

    def test_row_ceiling_truncates_and_flags(self):
        res = self.a.query("SELECT * FROM users", policy=QueryPolicy(max_rows=2))
        self.assertEqual(len(res["rows"]), 2)
        self.assertTrue(res["truncated"])
        self.assertTrue(res["receipt"]["truncated"])


class Refusals(unittest.TestCase):
    def setUp(self):
        self.a = ReadOnlyAdapter(make_db())
        self.addCleanup(self.a.close)

    def test_writes_refused_by_prefix(self):
        for sql in ("INSERT INTO users VALUES (9,'x',0)",
                    "UPDATE users SET balance=0",
                    "DELETE FROM users", "DROP TABLE users",
                    "PRAGMA journal_mode=WAL",
                    "ATTACH DATABASE 'x' AS y"):
            with self.assertRaises(QueryRefused, msg=sql):
                self.a.query(sql)

    def test_engine_level_denial_not_just_string_match(self):
        # a write smuggled past the prefix check still dies in the authorizer
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT * FROM users WHERE id IN "
                         "(SELECT id FROM users); DROP TABLE users")
        conn = make_db()
        self.addCleanup(conn.close)
        conn.set_authorizer(ReadOnlyAdapter._authorize)
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM users")     # engine denies directly

    def test_multi_statement_refused(self):
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT 1; SELECT 2")

    def test_unbound_placeholders_refused(self):
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT * FROM users WHERE name = ?")
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT * FROM users WHERE name = :n")

    def test_timeout_ceiling(self):
        # cross join large enough to trip the progress-handler deadline
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t(x INTEGER)")
        conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(2000)])
        a = ReadOnlyAdapter(conn)
        self.addCleanup(a.close)
        with self.assertRaises(QueryRefused) as ctx:
            a.query("SELECT count(*) FROM t a, t b, t c",
                    policy=QueryPolicy(timeout_s=0.2))
        self.assertIn("time ceiling", str(ctx.exception))

    def test_no_write_api(self):
        import e05.core as m
        for name in dir(m) + dir(ReadOnlyAdapter):
            for bad in ("insert", "update_", "delete", "execute_write",
                        "migrate"):
                self.assertNotIn(bad, name.lower())

    def test_data_unchanged_after_refusals(self):
        for sql in ("DELETE FROM users", "SELECT 1; DROP TABLE users"):
            try:
                self.a.query(sql)
            except QueryRefused:
                pass
        self.assertEqual(self.a.query("SELECT count(*) FROM users")["rows"],
                         [[3]])


if __name__ == "__main__":
    unittest.main()


class UpgradeRegressions(unittest.TestCase):
    """New tests for 0.1.1-partial fixes (A022-F1..F4)."""

    def setUp(self):
        self.a = ReadOnlyAdapter(make_db())
        self.addCleanup(self.a.close)

    def test_recursive_cte_allowed(self):          # A022-F1
        res = self.a.query(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL "
            "SELECT x+1 FROM c WHERE x < 5) SELECT count(*) FROM c")
        self.assertEqual(res["rows"], [[5]])

    def test_non_string_sql_refused_not_leaked(self):   # A022-F2
        for bad in (123, None, b"SELECT 1", ["SELECT 1"]):
            with self.assertRaises(QueryRefused):
                self.a.query(bad)

    def test_bad_params_type_refused(self):        # A022-F2
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT 1", 5)

    def test_literals_not_misread_as_placeholders(self):    # A022-F3
        self.assertEqual(self.a.query("SELECT 'a:b'")["rows"], [["a:b"]])
        self.assertEqual(self.a.query("SELECT 'x?y'")["rows"], [["x?y"]])
        self.assertEqual(self.a.query("SELECT ';'")["rows"], [[";"]])
        self.assertEqual(
            self.a.query("SELECT 1 -- trailing :note ;")["rows"], [[1]])

    def test_real_placeholders_still_enforced(self):    # A022-F3 negative
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT * FROM users WHERE name = :n")
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT ';', ?")
        with self.assertRaises(QueryRefused):
            self.a.query("SELECT 1; SELECT 2")   # real multi-statement

    def test_nonfinite_param_digest_strict(self):       # A022-F4
        nan, inf = float("nan"), float("inf")
        r1 = self.a.query("SELECT typeof(?)", (nan,))
        r2 = self.a.query("SELECT typeof(?)", (nan,))
        self.assertEqual(r1["receipt"]["params_digest"],
                         r2["receipt"]["params_digest"])
        r3 = self.a.query("SELECT typeof(?)", (inf,))
        self.assertNotEqual(r1["receipt"]["params_digest"],
                            r3["receipt"]["params_digest"])
        from e05.core import _canon
        import json as _json
        _json.dumps(_canon([nan, inf, -inf]), allow_nan=False)  # must not raise
