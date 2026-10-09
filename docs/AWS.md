# AWS status

No AWS account is connected from this repository.

Verified from the tree:

- There is no Terraform, CloudFormation, CDK app, or AWS deploy workflow.
- `.env.example` tells collaborators not to store AWS credentials here.
- Engine 2 exposes `collect_live_account`, and the implementation refuses to run. It does not call AWS.
- `GET /health` reports `aws` as `not_connected`.
- A twelve-action read-only IAM template is tested and is not attached to an account.
- ADR-002 and `docs/10_SECURITY_ETHICS_AND_OPERATIONS.md` require any future live collection to be read-only, least privilege, and explicitly authorized.
- Fixtures and foundry pins use synthetic or redacted records. They are not a live account export.

AWS service names, IAM action names, and ATT&CK cloud text in the foundry are reference data. They are not credentials and they do not grant access.

Do not add write permissions, account IDs, or raw policy documents to Git.
