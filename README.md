# Read-only SQLite Adapter

**0.1.2a1 — experimental partial candidate, JY-S025-P001 / E05**

Run bounded SELECT/CTE queries against a trusted SQLite database, with engine
authorization, bound parameters, typed results and unsigned query receipts.
Python 3.11+ with sqlite3 is required; there are no third-party runtime packages.

## Use

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from e05.core import ReadOnlyAdapter, QueryPolicy

with ReadOnlyAdapter.open_file("catalog.sqlite") as adapter:
    result = adapter.query(
        "SELECT id, name FROM products WHERE category = ? ORDER BY id",
        ("tools",),
        QueryPolicy(max_rows=100, timeout_s=2, max_result_bytes=1048576),
    )
    print(result["rows"], result["truncated"])
~~~

open_file opens an existing local file with an escaped SQLite URI and mode=ro.
It does not create missing databases and disables type converters, statement
caching and lock waiting. The path/database/schema must be trusted. It resolves
symlinks and is not a path confinement or race-resistant file-opening boundary.
SQLite's filesystem access and journal/WAL behavior still apply.

Alternatively, ReadOnlyAdapter(conn) takes ownership of a dedicated, exact
sqlite3.Connection, including closing it on close/context exit. Do not share or
use the connection separately after transfer. It replaces authorizer/progress
callbacks, row/text factories, busy timeout and extension-loading settings.
Existing uncommitted transactions are not committed; closing can roll them back.
The caller must trust existing converters, functions, collations, virtual tables,
extensions and global adapters. Python's original thread affinity still applies.
An in-process lock serializes adapter operations; it does not make a default
connection usable across threads or coordinate external access.

## Query controls

- Only SELECT or WITH shapes are accepted; SQLite authorizes the actual compiled
  operations and enforces one statement. Writes, DDL, transaction control,
  PRAGMA, ATTACH and reads of attached/temp databases are denied.
- Functions default to denied. A fixed list of common scalar/aggregate/window
  names is allowed; see FUNCTIONS in e05/core.py. Unknown and extension-loading
  functions are refused. A trusted host can override an allowed builtin name,
  so a name allowlist cannot prove that callbacks are free of side effects.
- Parameters use SQLite binding. Positional tuple/list or named dict inputs are
  snapshotted and validated. Values are exact None/int/float/str/bytes types;
  integers fit signed 64 bits, booleans/custom adapters are refused. Named keys
  are simple ASCII identifiers. SQLite validates binding counts/names; surplus
  named keys are accepted by SQLite and still included in the receipt digest.
- Always bind external values. The adapter cannot detect an f-string's origin,
  prove parameterization, or authorize which rows/columns a caller may read.
  SQL literals remain supported.
- Frozen policy values are checked again at query entry. The progress handler
  uses a monotonic clock, with deadline checks during fetching and before return.
  Busy waiting is disabled. Deadline failure returns no partial result.

The timeout is cooperative, not a hard wall-clock limit. It starts after input
validation and lock acquisition. SQLite callbacks, filesystem I/O, compilation,
individual native operations and cleanup can exceed it; it cannot stop a hung
trusted extension or impose a process memory/CPU/disk quota. Query plans can
create temporary disk data. Treat the process, runtime and database as trusted.

## Budgets

SQL: 64 KiB UTF-8; parameters: 256 entries, 256 KiB per text/blob, 1 MiB aggregate.
Each returned text/blob is at most 256 KiB. QueryPolicy accepts max_rows 1..10000
(default 1000), timeout_s finite 0.1..30 (default 2), and max_result_bytes
1024..8388608 (default 1 MiB). Booleans are not numeric policy values.

Engine limits during a query cap string/blob/encoded-row length at 1 MiB,
columns at 128, expression depth and compound SELECT terms at 64, variables at
256, VM program instructions at 250000, and LIKE/GLOB patterns at 4096 bytes.
Lower existing limits are respected; prior limits are restored after success
or refusal. These are workload controls, not complete SQLite resource isolation.

Rows are fetched incrementally with one lookahead row. A row ceiling returns a
prefix and truthful truncated flag; byte/value/engine failures refuse the entire
query. The result byte cap covers the exact compact ASCII-escaped JSON encoding
of columns and retained rows, excluding receipt/envelope overhead. Serialization
and the lookahead can temporarily consume more memory than the result cap.
Use ORDER BY for stable prefix order.

## Results and receipts

Columns include ordinal index, name and types observed in retained non-null
values. Duplicate names remain separate by index; empty/all-null columns report
unknown. This is observed result typing, not a declaration of the database schema.
Rows retain JSON-native values. BLOBs become {"type":"blob","base64":"..."}.
Nonfinite float results become {"type":"float","value":"inf"}, "-inf" or "nan".
SQLite normally converts a bound NaN to NULL; its input digest still records NaN.
The entire response is strict JSON serializable.

Receipt schema e05/query-receipt/v2 records adapter/SQLite versions, policy,
duration, row count, truncation, file mode and SQL/parameter/result digests.
Result digests bind both columns and rows; receipt_digest binds all other receipt
fields. Hashing uses explicit type tags, preventing string/tag and bytes/string
collisions. Positional lists/tuples share one sequence representation; mapping
order does not matter. Durations and database contents can change between calls.

read_only=true means the adapter applied its SQLite authorizer for that query.
The precise scope is also recorded in read_only_scope; it does not certify that
trusted callbacks or the host performed no external action. Hashes are unsigned
consistency/correlation values, not authentication, trusted execution evidence,
database snapshot identity or a tamper-proof audit log. No receipt is emitted for
refused queries. SQL text/parameters are not returned in receipts, but hashes can
reveal equality or low-entropy guesses; rows and exception causes can be sensitive.

## Verification and migration

58 tests: 18 inherited plus 40 new regressions. Source and installed-wheel checks
are recorded in [CHECK_RUNS](docs/CHECK_RUNS.json). CI covers Linux Python
3.11/3.12/3.14 and Windows 3.12. See [AUDIT](docs/AUDIT.md) and [SECURITY](SECURITY.md).

0.1.1-partial -> 0.1.2a1 requires Python 3.11+ for engine limit APIs. Function
names, parameter types, attached/temp access and bounds are stricter; max_rows
now tops out at 10000. Receipt schema/digest encoding changed; blob/nonfinite
wire values are tagged. Migrate consumers explicitly and do not compare v1/v2
digests. Ownership/close behavior is now explicit. No third-party runtime
dependency required an upgrade; Python/SQLite security updates remain the
operator's responsibility.

Other engines, credential management, pooling, tenant/row authorization, hostile
database isolation, the original 723-item program and formal certification remain
outside this partial candidate.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party source is vendored; see [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md).
