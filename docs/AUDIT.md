# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S025-P001 / 0.1.1-partial / run-0001 / product.
Reviewed SQL shape/binding checks, authorizer, connection lifecycle, limits,
result serialization and receipts. Original source remains separate.

## Findings repaired

- All SQL functions were authorized, including extension/custom function names.
  A fixed allowlist now denies unknown names; extension loading is disabled.
  Attached/temp reads are denied and authorization is reinstalled for each query.
  Host-overridden builtins and existing callbacks remain an explicit trust boundary.
- Claimed mandatory binding/interpolation detection was unsupported. Documentation
  now accurately requires caller binding; SQLite handles placeholder validation.
  A bounded scanner handles comments and all four SQLite quoting forms without
  treating quoted semicolons/question marks as executable tokens.
- Mutable/loosely typed policy and unbounded SQL/parameters/results allowed
  excessive work. Exact validated frozen policy, UTF-8/value/count limits,
  SQLite runtime limits and incremental result/byte caps now apply.
- Wall-clock deadlines and connection busy waiting undermined time controls.
  Monotonic cooperative progress/fetch/completion checks and no busy wait improve
  the guarantee; documentation explicitly excludes hard deadlines/OS containment.
- Cursors were left open and connection ownership unclear. Cursors close in
  finally, progress callbacks clear, prior engine limits restore, and adapters
  own/close dedicated connections. Fresh file opens use escaped URI mode=ro.
- Hashes conflated bytes/string and nonfinite/string values; blobs were not JSON
  serializable. Type-separated canonical hashes and tagged wire values repair
  this. Result hashes now bind column metadata and receipt hashes bind policy,
  flags, timing and version fields. No signature/authentication is claimed.

## Verification

18 baseline tests passed on Windows Python 3.12.14. All 58 source and installed-
wheel checks pass after changes, including 40 new cases: side-effect function
denial, extension/PRAGMA/attached reads, malformed quoting, strict types/budgets,
large native allocation refusal, row/byte limits, collision regressions,
column/receipt binding, timeout recovery, restored engine limits, factory reset,
mode=ro beneath the authorizer, escaped file paths and immediate locked-DB refusal.
Inherited test behavior is preserved; connection cleanup was added to fixtures.

CHECK_RUNS.json records current evidence and BASELINE_CHECK_RUNS.json retains the
historical report. CI covers Linux Python 3.11/3.12/3.14 and Windows Python 3.12.
The raised Python floor enables Connection.setlimit, introduced in Python 3.11.
No independent security certification, load benchmark, hostile DB isolation test,
723-item gate completion or build-tool vulnerability scan is claimed.

Version and receipt schema upgraded; packaging, pinned-action CI, README,
SECURITY, Apache 2.0 LICENSE and NOTICE name RUSSELL PHILIP SMITHSON.
No third-party code is vendored and no runtime package needed upgrading.

## Primary references reviewed

- [Python sqlite3](https://docs.python.org/3/library/sqlite3.html):
  parameter binding, callbacks, URI connections and runtime limits.
- [SQLite authorizer](https://www.sqlite.org/c3ref/set_authorizer.html):
  compilation authorization scope and callback actions.
- [SQLite limits](https://www.sqlite.org/limits.html): runtime workload limits.
