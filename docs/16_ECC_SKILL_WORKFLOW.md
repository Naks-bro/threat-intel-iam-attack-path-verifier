# ECC skills in the FYP workflow

ECC is an optional agent-workflow library, not an application dependency. Source: [affaan-m/ECC](https://github.com/affaan-m/ECC), pinned for this setup to commit `ef648e01899ba3e8dc6371642deaaf64b4477775` (plugin version `2.2.3`). The native Codex plugin makes the full ECC skill catalog available to this local Codex installation. A small, reviewable project-local subset is stored under `.cursor/skills/` for Cursor collaborators. Installing the plugin is not proof that a skill was used in a given task; the agent must read the applicable `SKILL.md` and report its effect.

The 13 project-local skill directories were copied byte-for-byte from that pinned commit; `ECC_LICENSE` retains the upstream MIT notice. Cursor discovers project skills in `.cursor/skills/` according to its [Agent Skills documentation](https://prod.cursor.com/docs/skills). `.cursor/rules/fyp-ecc-workflow.mdc` directs Cursor agents to this map. The Codex plugin is a local user installation, not a file in this Git repository; teammates need their own Codex install if they want the full catalog.

| FYP task | ECC skill to consider | Project-specific boundary |
|---|---|---|
| Change an Engine 1 ↔ portal or cross-engine API | `contract-first`, `fastapi-patterns` | `docs/03_ENGINE_CONTRACTS.md` stays Proposed until team acceptance; verify real serialized success and error paths. |
| Modify source normalization, rule compiler, or scenarios | `python-testing`, `tdd-workflow`, `eval-harness` | Use pinned artifacts and labeled cases; never describe corpus results as global accuracy. |
| Change foundry schema or PostgreSQL behavior | `postgres-patterns`, `database-migrations` | Use Alembic and disposable PostgreSQL tests; do not point an unreviewed migration at Supabase. |
| Change React review screens | `react-testing`, `frontend-a11y`, `browser-qa` | Preserve offline/partial/unavailable states and label fake AI, unpublished rules, and missing tools honestly. |
| Change reviewer or publication flow | `operator-approval-loop`, `security-review` | Human decision must bind to the exact immutable rule version and evidence hash. Login roles are not implemented. |
| Complete any substantial slice | `verification-loop`, `security-review` | Use this repo's commands below; disclose skipped live-DB or AWS checks. |

For the verification loop, run the repository commands rather than blindly copying a generic Node or Claude Code example:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy src
.\.venv\Scripts\python.exe -m pytest -m "not postgres"
Push-Location frontend
npm test
npm run build
Pop-Location
```

Run PostgreSQL and browser tests when the affected slice requires them. A passing offline preview never proves persistence. Security scanning should report file paths or counts, not print matching secrets. Review the dirty worktree before staging; unrelated Cursor/Codex changes belong to their authors.

No ECC hooks, MCP servers, autonomous loops, or global settings are required by this repository. Do not enable them merely because an ECC skill mentions them. Project-local skill copies are documentation/instructions only; they are not imported by the Python or React runtime.

Ruff excludes `.cursor/skills` because those pinned upstream instructions contain example Python and Markdown code blocks, not this application's source. Keep the copies byte-for-byte intact; do not reformat them to satisfy the FYP lint rules. The `src`, `tests`, `scripts`, and migration code remain subject to the normal checks.

## First use and verification — 2026-10-03

ECC's `verification-loop` was applied to the current FYP worktree using the project-specific commands above. The frontend build/type check, mypy (66 source files), Ruff lint/format (130 Python files), non-PostgreSQL pytest selection, and eight frontend tests passed. A heuristic source scan returned no candidate secret-bearing files and no frontend `console.log`; it is not a comprehensive secret audit. Coverage was not measured, and the PostgreSQL/Supabase path was not exercised. The worktree contains substantial pre-existing uncommitted implementation changes, so this verification is **not** a PR-ready claim. The native Codex plugin was confirmed installed and enabled with `codex plugin list --marketplace ecc --json`; its cache-reference check passed. These checks prove installation and this one skill use, not automatic use of every ECC skill.
