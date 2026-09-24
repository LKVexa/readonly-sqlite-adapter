# 0.1.2a1 — 2026-09-23

- Restrict function names/database scope and add mode=ro file connections.
- Bound SQL, bindings, engine work, retained rows and serialized result bytes.
- Use monotonic deadlines; close cursors and restore engine limits on refusal.
- Add typed strict-JSON results, schema-bound hashes and receipt schema v2.
- Require Python 3.11+, add 40 regressions, packaging and pinned-action CI.
- Include Apache 2.0 LICENSE/NOTICE and README; original certification remains open.

# Changelog — E05 Database Query Adapter (JY-S025-P001)

## 0.1.1-partial — 2026-09-14 (audit A022, run-0001)

Baseline: build-0001, product.zip sha256
`6c7219b4bcced758f4a2ba74f9f4ff622c579196d20f4f72620c9a3361f3d1ed`
(version 0.1.0-partial). All findings below were reproduced on the
baseline with live probes before fixing; repairs only, hence a patch
bump on the native `-partial` channel.

### Fixed

- **A022-F1** — `WITH RECURSIVE` queries, part of the documented
  SELECT/CTE-only capability, were denied by the sqlite authorizer
  (`SQLITE_RECURSIVE` missing from the allow set). Observed:
  `QueryRefused: engine denied non-read operation: not authorized`.
  Expected: recursive read-only CTEs execute. Fix: allow
  `SQLITE_RECURSIVE`.
- **A022-F2** — non-string `sql` (e.g. `query(123)`) escaped the
  documented `QueryRefused` contract with a bare `AttributeError`.
  Fix: type-check `sql` (str) and `params` (tuple/list/dict) and raise
  `QueryRefused`.
- **A022-F3** — the multi-statement and unbound-placeholder scanners
  misread characters inside string literals, quoted identifiers, and
  comments: legitimate reads such as `SELECT 'a:b'`, `SELECT 'x?y'`,
  `SELECT ';'` were refused. Fix: strip literals/identifiers/comments
  before shape checks; real placeholders and real multi-statements are
  still refused (negative tests added).
- **A022-F4** — receipt digests serialized non-finite floats with
  non-strict JSON tokens (`NaN`/`Infinity`). Fix: strict
  canonicalization (`allow_nan=False`) with tagged string forms for
  nan/inf; digests remain deterministic and nan vs inf digests differ.

### Compatibility

- No public API changes; no capability removed. Previously refused
  legitimate queries (recursive CTEs, literals containing `:`/`?`/`;`)
  now succeed; previously leaked exceptions now raise `QueryRefused`.
- Rollback: restore build-0001 product tree (sha above); no data
  formats changed.
