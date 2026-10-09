# Decisions and Open Questions

## Decision register

| ID | Decision | Status | Record |
|---|---|---|---|
| D-001 | Use two research stages and four engineering engines | Proposed for team acceptance | `decisions/ADR-001-two-stages-four-engines.md` |
| D-002 | Human approval and read-only live AWS are hard safety boundaries | Proposed for team acceptance | `decisions/ADR-002-human-approval-and-read-only-live-aws.md` |
| D-003 | Versioned contracts enable parallel engine development | Proposed for team acceptance | `decisions/ADR-003-contract-first-integration.md` |
| D-004 | Primary knowledge sources are MITRE ATT&CK Cloud, AWS TTC, and a pinned OWASP cloud-native document | Proposed | Pending ADR after access-format spike |
| D-005 | Earlier Neo4j baseline is superseded by proposed PostgreSQL-first snapshot/graph storage; portable JSON remains the engine contract | Superseded/proposed replacement, not migrated | `24_WHOLE_PRODUCT_SCHEMA_PROPOSAL.md`; measured need required before another graph store |
| D-006 | Policy Simulator is a pre-check with explicit limitations | Proposed | Pending implementation test |
| D-007 | CloudGoat verification is scenario-mapped and opt-in | Proposed | Pending guide/account-owner approval |
| D-008 | GNN and Redis are deferred until justified | Proposed | Pending vertical-slice measurements |
| D-010 | A source node may be one family or a combination. Strength counts distinct families. NVD and CISA KEV are pinned free feeds. AWS TTC waits. | Proposed | `decisions/ADR-007-source-strength.md` |
| D-011 | Engine 1 checkpoint is a pipeline portal with PostgreSQL. Product direction is superseded by the foundry. | Proposed | `decisions/ADR-008-engine1-curation-workbench.md` |
| D-012 | Engine 1 is an automated threat-to-rule foundry. The portal is a control plane. AI verifies and does not author rules. AWS TTC HTML is not an adapter. T1548 is not a precise IAM mapping. | Proposed | `decisions/ADR-009-threat-to-rule-foundry.md` |
| D-013 | Routine checks stay offline; marked database tests require an explicit disposable-loopback gate. Setup does not migrate or seed. | Proposed, locally implemented | `decisions/ADR-011-disposable-database-test-boundary.md` |
| D-014 | Exact verifier requests/results are retained separately from incomplete legacy AI rows; historical inputs never fall back to current pins. | Proposed, locally verified | `decisions/ADR-012-exact-verifier-records.md` |
| D-015 | Scoped exact-input review history is separate from incomplete legacy aliases; stored approval is not current eligibility or cloud authority. | Proposed, repository operations locally verified | `decisions/ADR-013-scoped-exact-input-review-history.md` |
| D-016 | Compute current scoped readiness separately from release/export; fake policy is benchmark-only and real/lab policy remains unconfigured. | Proposed, local API and isolated database checks verified | `decisions/ADR-014-computed-publication-assessment.md` |
| D-017 | Durable scoped stable releases preserve candidate bytes and recheck latest assurance/review at export; Engine 3 must request a fresh export. | Proposed, local API/database/restart verified | `decisions/ADR-015-scoped-stable-release-export.md` |
| D-018 | First real-account pilot compares two starting IAM identities from one authorized AWS project/account and one sealed snapshot, investigating one identity at a time. Neither comparator is an account-wide security verdict. | Accepted user direction, 2026-10-09; implementation remains proposed | `decisions/ADR-016-two-identity-iam-pilot.md` |

## Highest-priority open questions

### Product and academic scope

- What exact statement and title has the guide approved?
- Is the deliverable a research prototype, product prototype, or both?
- What minimum number of papers/datasets/scenarios does the department require?
- What evidence is required to support a novelty claim?

### Repository and implementation

- Where is the reported Engine 1 parser repository?
- Which code was authored by the team versus generated in chats?
- What Python and dependency versions are supported?
- Is there any implementation for Engines 2–4?

### Sources and rules

- What official export/API or stable snapshot will be used for AWS TTC?
- What is the exact supported rule DSL and AWS action/resource vocabulary?
- Who may approve a rule, and is approval scoped by environment/dataset?

### AWS semantics

- Single account or Organizations/multi-account?
- Which services' resource policies are supported in v1?
- Are SCPs, RCPs, session policies, VPC endpoint policies, ABAC/tag conditions, and cross-account access in scope?
- How will missing context be represented and tested?

### Verification and safety

- Which first escalation pattern and CloudGoat scenario will be used?
- What credentials and permissions are required for simulation?
- Who authorizes sandbox runs, spending, and cleanup acceptance?
- What evidence threshold distinguishes supported, inconclusive, and sandbox-verified?

### Evaluation

- Who labels the gold datasets and resolves disagreement?
- How many independent reviewers are available?
- What baselines and statistical tests are feasible?
- Which artifacts can be published without exposing sensitive information?

## Decision procedure

For each open question, record owner, deadline, evidence considered, decision, alternatives, consequences, and affected contracts. Do not resolve high-impact questions only in chat; create or update an ADR.
