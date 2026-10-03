# Recovery

Clone the GitHub repository on a new machine and check out `engine1-curation-workbench`. `main` is an older fixture baseline.

```text
https://github.com/Naks-bro/threat-intel-iam-attack-path-verifier.git
```

## Software

- Python 3.12 (`requires-python` is `>=3.12,<3.13`)
- Node.js 22, matching GitHub Actions
- Git
- Docker, only if you want the local Postgres service in `compose.yaml`

## Setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
cd frontend
npm ci
```

From `frontend`, `npm test` and `npm run build` check the portal. From the repository root:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pytest -m "not postgres"
.\.venv\Scripts\python.exe -m mypy src
```

PostgreSQL integration tests run in GitHub Actions. Locally they run only when `FYP_DATABASE_URL` is set.

## Environment variable names

Copy `.env.example` to `.env`. Fill the values on the new machine. Do not commit `.env`.

- `FYP_IAM_MODE`
- `FYP_DATABASE_URL`
- `FYP_MIGRATION_DATABASE_URL`
- `FYP_DATABASE_DIRECT_URL`
- `FYP_DATABASE_SESSION_URL`
- `FYP_DATABASE_SSLROOTCERT`
- `FYP_POSTGRES_PASSWORD` for Docker Compose only

The database password, API keys, and certificates are not in Git. Reset the database password in the Supabase dashboard if the previous one was exposed, then put the new password only in `.env`.

## Managed PostgreSQL

An optional Supabase project holds the demonstration database. The application uses SQLAlchemy and does not import a Supabase client.

- Project name: `FYP`
- Region: `ap-southeast-1`
- Project reference: `ixjdhqjcuajxzaiusbkw`
- Direct host form: `db.ixjdhqjcuajxzaiusbkw.supabase.co`, port `5432`
- Use `sslmode=require`. Use `verify-full` only when `FYP_DATABASE_SSLROOTCERT` points at a CA file.
- Do not use the transaction pooler on port `6543` for this API.

After `.env` exists:

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.persistence check
.\.venv\Scripts\python.exe -m fyp_iam.persistence migrate
.\.venv\Scripts\python.exe -m fyp_iam.persistence seed
```

Then start the API and the portal as described in [DEPLOYMENT.md](DEPLOYMENT.md). `GET /health` should report `database` as `available` when migrations are current.

## What a clone does not restore

- `.env` and any CA file under `certs/`
- `frontend/node_modules/` and the Python virtual environment
- Chat exports that live outside this repository
- Screenshot files under `artifacts/` if they were left untracked
