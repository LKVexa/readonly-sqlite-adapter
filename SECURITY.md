# Security boundaries

Use a trusted Python/SQLite runtime, host, database/schema and connection. Prefer
open_file for fresh mode=ro connections. Never transfer a connection that contains
untrusted callbacks, converters, collations, virtual tables or extensions.
Allowed function names can be overridden by host code. A database authorizer
does not confine Python/native code or prevent filesystem/network side effects.

All readable main-database rows and schema metadata may be queried. There is no
tenant identity, row/column authorization, secret redaction or injection-origin
detection. Bind external values and impose application authorization separately.
Query/results can expose sensitive data; SQLite exception causes can carry
internal details. Use synthetic data when reporting defects.

Limits and deadlines bound normal workloads but do not provide a hard process
quota or latency guarantee. Trusted callbacks, native work, disk I/O and cleanup
can outlast the deadline. SQLite temporary storage is not a bounded filesystem.
Do not share or externally modify an owned connection. Closing may roll back
uncommitted caller transactions. A caller with process access can disable controls.

Digests are unkeyed and forgeable. Receipts are not authenticated audit records
or evidence that the database/query facts are true. Keep runtimes patched.
No third-party runtime dependency, build-tool vulnerability scan, hostile-input
OS sandbox assessment or original program certification is claimed.
