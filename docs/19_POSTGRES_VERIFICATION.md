# Local PostgreSQL quality-storage verification

## Result — 2026-10-03

**Verified locally:** P6.2's fresh migration, repeat-run artifact idempotency,
partial-report history, stored API response, and actual PostgreSQL restart
durability. A reconstructed pre-0005 schema upgraded without changing its seeded
legacy validation row or inventing a report. This is not a Supabase deployment,
production-scale migration test, authenticated portal, or release approval.

## Isolated environment

- PostgreSQL 17.11 Windows x64 portable runtime; no Windows service installed.
- Download discovered through [EDB's official archive page](https://www.enterprisedb.com/download-postgresql-binaries), link file ID `1260616`.
- Resolved archive: `postgresql-17.11-5-windows-x64-binaries.zip` on `get.enterprisedb.com`.
- Observed SHA-256: `80379b2c04d51c30225532e0ae04509899141e9957ed096fe749d7fd9df8f82f`.
- The executable reported `NotSigned`; the recorded hash is a local integrity fingerprint, not independently published authentication of the binary.
- Private cluster listened only on `127.0.0.1:55432`, with SCRAM password authentication and a newly generated test password.
- Test database names: `fyp_iam` and `fyp_iam_legacy`, created inside this owned cluster.
- All five database configuration variables were explicitly overridden in the child process; no managed endpoint was selected.
- No project `.env`, managed database, application API, or portal process was changed.

Initialization/startup followed PostgreSQL's [initdb](https://www.postgresql.org/docs/17/app-initdb.html)
and [pg_ctl](https://www.postgresql.org/docs/17/app-pg-ctl.html) documentation.
On Windows, capturing a background server's inherited output pipe caused the
first one-off wrapper to hang even though the server was ready. That test server
was intentionally stopped; the wrapper was corrected to use detached output for
`pg_ctl`, and a second owned cluster completed verification. This was a test-tool
failure, not an application migration failure.

## Observed commands and guarantees

| Check | Observed result | What it proves |
|---|---|---|
| `python -m alembic upgrade head` | Exit 0 through `20261003_0005` | Current fresh schema migrates on PostgreSQL 17.11 |
| `python -m pytest -m postgres -o addopts= -q` | 5 passed, 198 deselected | Existing persistence/privacy checks plus report deduplication, partial history, tamper rejection, and stored API/404 response |
| Stop/start cluster, then read rule through a new engine | Exact before/after dossier equality | Stored rule and quality report survive an actual database restart |
| `python -m alembic upgrade 20261003_0004`, reconstruct earlier boundary, seed legacy row, then upgrade head | Exit 0 | Migration 0005 handles missing report tables and a NOT NULL legacy duration column |
| Read seeded legacy row after upgrade | Duration remained `9`; column became nullable; report table stayed empty; rule report remained null | No destructive backfill or inferred success |

The legacy boundary was deliberately reconstructed, not copied from Supabase:
the two **empty** quality tables introduced indirectly by migration 0002's
current-metadata import were removed in the owned legacy test database, and its
duration column restored to NOT NULL before seeding. This distinction matters:
the check verifies that boundary, not every historical or production database.

The three quality integration tests are in
`tests/integration/test_foundry_quality_postgres.py`. They require a migrated,
disposable loopback database named `fyp_iam`; deliberate partial/tampered writes
roll back. Do not run the existing PostgreSQL suite against managed databases:
some tests create API roles for permission checks.

The one-off restart/migration harness remains at
`C:/Users/Nakul.kokate.SSTLRGLAP-075/AppData/Local/Temp/fyp-pg17-1791024176678/verify.py`.
It is local verification evidence, not a portable project setup command or CI
dependency. Test clusters are stopped; temporary cleartext initialization-password
files were removed. Runtime and test data are retained outside the repository.

## Remaining end-to-end work

Permanent automated restart/legacy-boundary test orchestration, current remote
CI, managed deployment/backup/rollback verification, measured validator runtime,
and production-scale migration behavior remain separate release work. Engine 1
still requires the other rule families, exact-version human review, enforced
stable publication, run/version comparison UI, and reproducible experiments.

No result above makes the overall Engine 1 goal complete.

Final regression checkpoint after adding the null/partial route contracts:
200 non-PostgreSQL tests passed, five PostgreSQL tests deselected in that run;
the five live PostgreSQL tests had passed separately in the owned cluster.
Mypy passed 68 source files, Ruff lint/format passed, and diff whitespace checks
passed. One existing Starlette/httpx deprecation warning remains. No frontend
implementation changed in this verification turn, and no new browser or current
remote CI pass is claimed.
