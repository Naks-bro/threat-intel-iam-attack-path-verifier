# Decisions and Open Questions

## Decision register

| ID | Decision | Status | Record |
|---|---|---|---|
| D-001 | Use two research stages and four engineering engines | Proposed for team acceptance | `decisions/ADR-001-two-stages-four-engines.md` |
| D-002 | Human approval and read-only live AWS are hard safety boundaries | Proposed for team acceptance | `decisions/ADR-002-human-approval-and-read-only-live-aws.md` |
| D-003 | Versioned contracts enable parallel engine development | Proposed for team acceptance | `decisions/ADR-003-contract-first-integration.md` |
| D-004 | Primary knowledge sources are MITRE ATT&CK Cloud, AWS TTC, and a pinned OWASP cloud-native document | Proposed | Pending ADR after access-format spike |
| D-005 | Neo4j is the graph persistence/query baseline; portable JSON remains the engine contract | Proposed | Pending benchmark |
| D-006 | Policy Simulator is a pre-check with explicit limitations | Proposed | Pending implementation test |
| D-007 | CloudGoat verification is scenario-mapped and opt-in | Proposed | Pending guide/account-owner approval |
| D-008 | GNN and Redis are deferred until justified | Proposed | Pending vertical-slice measurements |

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
- Which OWASP project/release is in scope?
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

