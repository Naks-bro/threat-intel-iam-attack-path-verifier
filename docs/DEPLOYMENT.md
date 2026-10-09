# Deployment

Production deployment is not configured. This repository has no hosting provider, container registry, Terraform stack, or release workflow.

## What runs today

Local demonstration, from the repository root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn fyp_iam.api.app:create_app --factory --host 127.0.0.1 --port 8765
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

The portal is `http://127.0.0.1:5173`. The API is `http://127.0.0.1:8765`. Vite proxies `/health` and `/v1` to the API. The browser does not open the database.

A database-free preview is `python -m uvicorn fyp_iam.api.preview_app:app --host 127.0.0.1 --port 8765`. That process ignores `FYP_DATABASE_URL` and does not publish a rule.

## Persistence

PostgreSQL is optional for local development. SQLAlchemy, Psycopg, and Alembic are the implementation. `compose.yaml` can start Postgres 16 when Docker is installed and `FYP_POSTGRES_PASSWORD` is set in the environment. The Compose file contains no password.

Copy `.env.example` to `.env` for a private database URL. Commands:

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.persistence check
.\.venv\Scripts\python.exe -m fyp_iam.persistence migrate
.\.venv\Scripts\python.exe -m fyp_iam.persistence seed
.\.venv\Scripts\python.exe -m fyp_iam.persistence verify-restart
```

## Continuous integration

`.github/workflows/workbench.yml` runs on push and pull request:

- unit: Ruff, format, unit tests, mypy
- frontend: npm ci, component tests, production build
- postgres: Postgres 16 service, Alembic, integration tests, one Playwright flow

That workflow uses an ephemeral database password `ci-only`. It does not deploy and does not use a managed-host secret.
