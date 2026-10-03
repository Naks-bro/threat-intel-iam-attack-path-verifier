# Changelog

Older history is `git log`. This file records the workbench branch after it diverged from `main` at `a0810bf`.

## 2026-10-03

- Recorded recovery, deployment, and AWS status for a new machine. GitHub remains the source of truth.
- Preserved the local foundry persistence work: Alembic schema `foundry`, optional Supabase connection settings, and the portal that reads stored rules.
- `engine1-curation-workbench` already contained the pinned source-to-experimental-rule slice through `0b682f5`.

## Already on `engine1-curation-workbench`

- `0b682f5` Record the stored-row foundry CI run.
- `544737f` Start the portal flow from an empty registry.
- `484f5f9` Compile the credential rule from stored evidence.
- `386aff1` Record the green foundry CI run.
- `3b2892c` Flush foundry parent rows before their evidence links.
- `af7e9d4` Replace the single-record page with the foundry control plane.
- `cf6a128` Replace the checkpoint tables with a pinned source-to-rule foundry slice.
- `b05356e` Record the foundry redirect and the checkpoint schema gaps.
- `ddcc160` Record the green PostgreSQL CI run without calling the local database operational.
- `edf546e` Flush each workbench parent row before inserting its children.
- `d01a228` Keep pinned artifact bytes stable and insert parent rows before claims.
- `d41074a` Record that local PostgreSQL is unavailable while the workbench slice is in the checkout.
- `a8ec9a2` Show the pinned T1548 review in the React workbench.
- `3e29320` Add the PostgreSQL workbench store and fail closed when it is unreachable.
- `dcc28d0` Record the Engine 1 audit and the proposed curation workbench.
- `639f34f` Preserve the tested local prototype before the Engine 1 workbench.
