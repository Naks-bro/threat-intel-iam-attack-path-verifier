# Local PostgreSQL quality-storage verification

## Scoped stable-release checkpoint — 2026-10-07

**Verified locally:** twelve gated PostgreSQL tests passed on the isolated
PostgreSQL 17.11 runtime. Real HTTP exercised stable creation/retry/export,
wrong-scope refusal, corrupted-release unavailability, later rejection blocking
export/new publication, real-scope refusal and the fresh Engine 3 consumer seam.
The canonical candidate stayed byte-identical. Engine 3 reported its currently
unsupported precondition, not a finding or exploitability.

A reconstructed populated 0007 upgraded to `20261007_0008` without changing the
earlier dossier. Actual stop/start retained exact review/verifier history and an
eligible benchmark fake-policy release with byte-identical gated export.
The first attempt exposed a test-only raw-versus-canonical JSON whitespace
comparison; the corrected test checks unchanged bytes and canonical semantics.
The successful run used a fresh owned cluster, not a restart of that failed job.

All owned test clusters are stopped; the initialization password file is absent.
No managed migration, cloud/provider call, actual human approval or browser
release flow occurred. `467` non-PostgreSQL tests, Ruff, mypy (83 sources) and
four existing generated contracts also passed. ADR-015 records remaining limits.

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

## Foundation gate verification — 2026-10-03

A fresh owned cluster using the same portable runtime accepted the new
disposable-database gate, migrated 0001–0005, and passed all five marked
PostgreSQL tests (247 other tests deselected). An actual stop/start preserved
the stored dossier and quality report. The owned cluster was then stopped;
no listener remains on its port, and the temporary initialization password
file was removed. Earlier test clusters and application configuration were
preserved. This rerun did not repeat the reconstructed legacy-schema upgrade
or the remote CI portal/reset workflow, and did not touch Supabase.

The one-off helper and stopped data remain outside Git. They are diagnostic
evidence, not a portable installation dependency or a managed deployment.

## Exact verifier retention — 2026-10-03

Migration 0006 and the opt-in `verify-run` path were checked on separate owned
PostgreSQL 17.11 clusters using the same portable runtime and disposable-target
gate. Random test passwords stayed in the helper process and a temporary init
file, which was removed. Application `.env` and managed databases were not used.

The initial run caught `DuplicateTable`: migration 0002 imports current model
metadata and already created the packet table. Migration 0006 was corrected to
use `IF NOT EXISTS`, consistent with the preceding additive quality migration.
The failed test cluster was stopped and preserved, not reset.

Two distinct subsequent checks passed:

- Populated older-schema shape: migrate through 0005, remove only the empty
  packet table introduced by current metadata in this owned test database, seed
  the legacy run, upgrade to 0006, confirm the prior dossier is unchanged, and
  run all six marked PostgreSQL tests. Actual stop/start preserves the latest
  exact request/result. This reconstruction is not every historical schema.
- Empty installation: migrate from empty through 0006, perform the first bound
  persisted run, execute the real `verify-run` CLI and confirm exact packet
  equality after an actual stop/start. This verifies the fresh-install metadata
  interaction separately from the populated upgrade.

Latest offline regression: 298 passed, six PostgreSQL tests deselected, Ruff
lint/format passed and mypy passed 73 source files. One existing Starlette warning
remains. Frontend/browser code was unchanged and its earlier checks were not rerun.

The one-off helper `verify_packets.py` and stopped `cluster-verifier-*` data remain
under the previously recorded local Temp runtime directory, outside Git. They
are diagnostic artifacts, not a portable setup dependency, and must not be rerun
unchanged against existing paths. No managed migration, backup/restore, API/GUI
packet inspection, remote workflow or DBA-level immutability is claimed.

## Future reruns (safety gate)

### Operator-review GUI checkpoint — 2026-10-03

The new owned `cluster-review-ui-20261003` migrated through 0007 and passed all
ten marked tests. An explicitly configured test-operator API and actual portal
recorded a synthetic-benchmark revision using keyboard controls and displayed it
after page reload; no HTTP mocks were used. The browser checked four widths,
captured the panel and observed only successful review responses. The normal CLI
and verifier packet stop/start retention also passed. This specific helper mode
did not separately compare GUI-created review history across database restart;
the earlier scoped-review/HTTP helpers provide their independently recorded
restart evidence. Both owned services were stopped and the temporary init
password removed. This is not a real human approval or managed/live AWS workflow.

### Local review HTTP checkpoint — 2026-10-03

A new owned `cluster-review-api-20261003` repeated the populated 0006→0007
upgrade check and passed ten marked tests. The real API retained a review,
returned identical retries, isolated the lab scope, rejected stale quality
bindings and returned sanitized unavailable for a corrupted stored record hash.
The test restored that hash. Actual stop/start retained exact review/verifier
history. The helper stopped the cluster and removed the temporary password file.
HTTP used the ASGI TestClient over real PostgreSQL; no live network/browser
review journey, managed deployment, stable export or AWS action is implied.

### Scoped-review repository checkpoint — 2026-10-03

A new owned `cluster-scoped-review-20261003` first migrated through 0006.
Because migration 0002 imports current ORM metadata, the helper verified the
new `scoped_reviews` table was empty and removed only that table in this new
disposable cluster to reconstruct the pre-0007 schema. It populated the normal
foundry and upgraded through 0007; the earlier dossier remained identical and
no legacy approval was inferred. Nine marked tests passed, including scope
isolation, idempotent retries, stale/conflicting requests and opposing history.
Actual stop/start retained exact review and verifier records. The helper stopped
the cluster and removed its temporary password file. No managed migration,
review API/UI, stable export, authenticated identity or AWS action was tested.

### Normal pipeline checkpoint — 2026-10-03

A fresh owned `cluster-normal-20261003` migrated through 0006 and passed seven
marked tests. A normal API POST retained a three-source verifier packet; corrupting
one stored source payload then caused a sanitized 503 with no additional pipeline
or packet rows. The prior dossier remained readable, and the test restored the
payload. The ordinary CLI `run` passed. A real loopback API and portal browser flow
created another run and displayed the retained source metadata (no HTTP mocks).
Actual PostgreSQL stop/start preserved the exact latest packet. Both owned
services were stopped and the temporary init password file removed. The stopped
cluster/helper remain outside Git; do not rerun against its existing path.
This is not Supabase deployment, live AWS analysis or a complete browser QA audit.

### Subsequent dossier checkpoint — 2026-10-03

A fresh owned loopback cluster migrated through 0006 and passed all six marked
PostgreSQL tests. The bound-packet test now exercises the real rule HTTP route:
request/response digests match the compiled record, all three source metadata
entries are present, and raw source text is absent. Actual stop/start retained
the packet. The helper stopped the cluster and removed its temporary password
file. `cluster-dossier-20261003` remains outside Git as stopped diagnostic data.
Separate browser fixtures test presentation only, not a browser connected to
this cluster. No managed database, cloud inventory or backup restore was tested.

The original quality-storage evidence above predates the disposable-database safety gate.
New marked-test runs require `FYP_ALLOW_DISPOSABLE_DATABASE_TESTS=1` and a matching
loopback `fyp_iam` target. Run `python -m fyp_iam.persistence.test_guard` before
migration/test commands; see ADR-011 and the foundation runbook. This note does
not retroactively claim the updated CI workflow was executed.
