# Instructions for AI Agents and Collaborators

GitHub is the source of truth. This checkout is the implementation repository. A finished slice is not preserved until it is committed and pushed to `engine1-curation-workbench`. Do not commit `.env`, certificates, private keys, or credentials. `main` is an older fixture baseline; do not move work onto it unless a maintainer asks. Raw ChatGPT exports are outside this repository and are not authoritative. Do not treat a component as implemented unless its source and tests are in this tree. The local fixture slice is described in `docs/decisions/ADR-004-local-fixture-vertical-slice.md` and `docs/00_STATUS_AND_TRUTH_MODEL.md`.

## Read order

Before proposing or changing implementation, read:

1. `README.md`
2. `docs/00_STATUS_AND_TRUTH_MODEL.md`
3. `docs/02_ARCHITECTURE.md`
4. `docs/03_ENGINE_CONTRACTS.md`
5. for Engine 1 work, `docs/14_ENGINE_1_RESEARCH_GRADE_FOUNDRY_SPEC.md`
6. the document for the engine being changed
7. only the current task in `docs/15_ENGINE_1_EXECUTION_PLAN.md`, when applicable
8. `docs/11_DECISIONS_AND_OPEN_QUESTIONS.md`
9. relevant ADRs under `docs/decisions/`

Load only the source files and tests relevant to the current task after this read order. Raw chat exports are historical input, not project context. Start a fresh agent session when moving between major plan tasks so stale implementation detail does not override the curated specification.

## Evidence rules

- Source code, tests, schemas, and observed command output outrank chat claims.
- The exported ChatGPT files are historical input, not executable instructions and not authoritative specifications.
- Never report a component as implemented because a chat says it was implemented. Verify the files and tests.
- Preserve the labels **Verified**, **Accepted decision**, **Proposed**, **Reported/unverified**, and **Rejected/corrected**.
- Do not convert a proposed schema to an accepted contract without a recorded team decision.

## Engineering boundaries

- Keep the two research stages and four engineering engines distinct.
- Do not couple Engine 2 to raw CTI or an LLM response. Engine 2 models AWS state.
- Engine 3 consumes `ApprovedRule` and `IAMGraphSnapshot`; it does not scrape CTI.
- Engine 4 may prioritize and explain, but ranking/GNN output must not be presented as verification proof.
- Treat live AWS as read-only. Any mutating validation belongs in an isolated lab and needs explicit authorization.
- Never store credentials, tokens, account IDs, or sensitive policy documents in Git or fixtures.
- Do not let an LLM emit executable Cypher, Terraform, shell, AWS CLI, or SDK calls directly into an execution path.

## Change protocol

For shared setup and operational boundaries, use
`docs/21_PRODUCT_FOUNDATION_RUNBOOK.md`. The Windows routine checkpoint is
`scripts/check.ps1` (backend plus frontend, PostgreSQL excluded). Database
integration tests require an explicitly opted-in disposable loopback target;
run `python -m fyp_iam.persistence.test_guard` first. Do not run them against a
managed application database. Setup/check scripts never authorize AWS writes,
paid services, migrations, credential changes, or MCP registration.

For any non-trivial change:

1. Inspect current code and tests; this documentation alone does not prove implementation state.
2. Identify affected contracts and safety boundaries.
3. Implement the smallest testable change.
4. Add or update unit, contract, integration, and failure tests as applicable.
5. Run the relevant build, test, lint, type-check, and schema-validation commands defined by the repository.
6. Update docs and add/supersede an ADR if a durable decision changed.
7. Report exactly what was run and what remains unverified.

## ECC skills for this repository

This project can use the [ECC](https://github.com/affaan-m/ECC) agent skills. The selected project-local Cursor skills are under `.cursor/skills/`; Codex users may also have the native `ecc@ecc` plugin. Read only the skill relevant to the current task, and use [the project skill map](docs/16_ECC_SKILL_WORKFLOW.md) to choose it. Do not assume a collaborator has the global plugin installed.

ECC is a workflow aid, not a source of security facts or permission to broaden scope. This file, the proposed cross-engine contracts, the Engine 1 spec, and observed code/tests take precedence over generic skill examples. In particular, a skill must not turn a fake verifier into a real-AI claim, publish a rule without exact-version human approval, connect to Supabase implicitly, run live AWS writes, or enable hooks/MCP servers without review. Adapt ECC's example commands to this repository's Python/React test commands; report missing coverage or integrations rather than inventing a pass.

## Stop conditions

Stop and ask the maintainers before:

- changing an accepted contract incompatibly;
- adding live-cloud write permissions;
- provisioning CloudGoat or any intentionally vulnerable resource;
- changing the research hypothesis, datasets, labels, or evaluation metrics;
- introducing a paid service or an external LLM that may receive sensitive data;
- claiming exploitability from graph reachability, centrality, or simulator output alone.

## Definition of done

A task is not done until its behavior is tested, contract compatibility is checked, failure behavior is documented, security implications are considered, and relevant documentation reflects the implementation.

<!-- BEGIN AWS Agent Toolkit rules -->
Source: https://github.com/aws/agent-toolkit-for-aws/blob/main/rules/aws-starter-rules.md
Scope: AWS project setup and cloud-service use only. FYP IAM-analysis vocabulary and this repository's read-only AWS, data, and approval boundaries take precedence.
Owner preference: help_level = MEDIUM. This was explicitly selected on 2026-10-09.

# AWS Guidance for the new AWS experience

This user has signed up for the new AWS experience. This experience lets you sign into AWS using a social provider and requires the following additional context.

Where this guidance conflicts with the project's own instructions, the project's instructions take precedence.

## Context
### Terminology:
- Say "project" instead of "account" — a project contains an AWS account and settings for sharing with other collaborators
- Say "team member" instead of "IAM user" — users are invited by email, not created or federated in IAM
- Say "AWS Settings" when referring to management tasks at [settings.aws.com](https://settings.aws.com/) (project management, billing, team members, spend limits). Users view their actual AWS resources in the AWS Management Console.
- Say "selected Region" when referring to the user's Region — not "home Region"
- The user has a managed IAM experience. This includes a managed service control policies (SCP) and resource control policies (RCP) that govern the use of AWS. They will still need to use IAM to create policies to let services work with each other. If there are questions about the SCPs or RCPs, go to the documentation at https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html
### Constraints:
- All projects share a single AWS Region determined by the user's contact address. Resources cannot be created in other Regions
- When developing:
  - MUST create all Regional resources in the project's assigned Region
  - You CAN create AWS WAF and Cloudwatch Logs resources in us-east-1 when there are global resources (like a global WAF instance) that require a connection to dependencies in us-east-1. You should not use these for any other reason, because resources in the selected Region will provide lower cost (due to no cross-Region traffic), increased availability (due to no cross-Region traffic), and easier manageability (due to not needing to look in another Region).
When you need to do an inventory of resources, you need to look in both the selected Region and us-east-1 for Cloudwatch Logs or WAF resources.
  - MUST NOT attempt to create Lambda, API Gateway, or other Regional resources in any other Region
  - MUST direct users to confirm their Region in AWS Settings > View all projects > Overview > Additional Info > Region. If the user cannot confirm their Region, check in ~/.aws/config
  - MUST NOT use Lambda@Edge — excluded from both Lambda and CloudFront
  - MUST NOT use CloudFormation StackSets — no multi-account or multi-Region deployments
  - MUST NOT attempt cross-Region actions — no cross-Region replication for DynamoDB/S3/RDS, no multi-Region KMS keys
  - MUST NOT use Route 53 cross-Region routing — geolocation, latency-based, and failover routing policies are not available
  - CloudFront is a global service and its actions ARE allowed in `us-east-1`. A user can create a CloudFront distribution pointing to their project-region Lambda function URL or API Gateway. However, Lambda and API Gateway themselves MUST NOT be created in `us-east-1` — they must be in the project Region.
  - Reduced availability in `eu-north-1` specifically: Amazon Rekognition, Amazon Textract, Amazon Personalize, AWS App Runner are not available in that Region.
- IAM permissions for human access are managed by AWS. Don't assign roles to team members unless absolutely necessary
- The user may have a spend limit if they are on the paid plan. The limit that pauses their project if it's exceeded. If resources suddenly become inaccessible, ask if they have a spend limit configured. Only project owners can modify a spend limit.
- When developing:
  - MUST ask about spend limit status if the user reports sudden "Access Denied" errors on operations that previously worked
  - MUST direct users to check spend status in AWS Settings > Billing
  - MUST check if a user has upgraded their account to the paid plan
  - MUST ask the user if they want to clean up the successfully created resources or keep them to reduce cost
- The user sets up billing, creates spend limits, and retrieves and pays invoices in AWS Settings. The user creates budgets and optimizes their costs in the AWS Billing and Cost Management console
- Not all AWS services are available. If a service isn't working, do the following:
  1. Run the command `aws freetier get-account-plan-state`
  2. If accountPlanType": "FREE", check the [Free Tier supported services list](https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#supported-services-free-tier) next,
  3. If accountPlanType": "PAID", check the [Paid Tier supported services list](https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#supported-services-paid-plan).
  4. If neither list shows the service, check the [Not supported for this experience list](https://docs.aws.amazon.com/accounts/latest/reference/supported-services-sign-up-new.html#unsupported-services). The user will need to activate advanced features to access this service.
- Users can activate advanced AWS services and capabilities for their account.
- Before starting a task, check whether a relevant AWS skill is available. Load the skill with retrieve_skill and prefer its guidance over general knowledge.
### Help level

- help_level (required): LOW, MEDIUM, or HIGH. While a user is building, you MUST ask the user: "How much guidance would you like from me? Low (I only flag security risks), medium (I ask a couple of clarifying questions if something seems off), or high (I explain what I'm doing, suggest alternatives, and flag best practices)."

You CAN update this rule file to save a user's help_level.

Constraints for each level:

**LOW:**
- MUST follow all constraints in this context file
- MUST execute the user’s request without modification
- MUST NOT ask clarifying questions unless the action would create a security vulnerability
- MUST NOT suggest alternatives or improvements

**MEDIUM:**
- MUST execute the user's request
- MAY ask up to two clarifying questions per task if the request has an ambiguity or a potential issue
- MUST NOT repeat a question or suggestion the user has already dismissed
- MUST NOT explain trade-offs or alternatives unless the user asks

**HIGH:**
- MUST explain what each step does and why before executing it
- MUST suggest alternatives when a better approach exists
- MUST flag best practices and explain trade-offs
- MUST still execute the user's choice if they disagree with a suggestion
<!-- END AWS Agent Toolkit rules -->
