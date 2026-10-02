# Source and Verification Register

Checked: 2026-10-02

Use this register for architecture facts only. The academic report still needs a full paper-by-paper bibliography audit.

## Primary technical sources

| Source | Supports | Important limitation/use |
|---|---|---|
| [MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/) | ATT&CK data is available as STIX and through the official TAXII server; Excel is human-oriented | Pin ATT&CK/source version because content changes |
| [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/) | Cloud-relevant tactics and techniques exist in the Enterprise matrix | Technique descriptions are not structural IAM rules |
| [AWS CIRT launch of the Threat Technique Catalog for AWS](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-launch-of-the-threat-technique-catalog-for-aws/) | AWS TTC is based on ATT&CK Cloud and includes AWS-specific observed techniques, mitigations, and detections | A blog/catalog is not automatically a stable API; verify ingestion format |
| [OWASP Cloud-Native Application Security Top 10](https://owasp.org/projects/cloud-native-application-security-top-10) | The project provides education/guidance for secure cloud-native adoption | Treat as curated guidance, not a live CTI feed |
| [AWS IAM policy simulator documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html) | Simulator evaluates supplied/in-scope policies without making a real service request; documents unsupported/different cases | Does not prove exploit execution; context and policy coverage matter |
| [AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) | Effective authorization combines multiple policy types and explicit denies | Engine 2 must report unsupported/missing policy layers |
| [Boto3 IAM client reference](https://docs.aws.amazon.com/boto3/latest/reference/services/iam.html) | Programmatic IAM listing and simulation operations are available through the AWS SDK | Each collector call still requires scoped permissions and pagination/error handling |
| [CloudGoat repository](https://github.com/RhinoSecurityLabs/cloudgoat) | Curated, intentionally vulnerable standalone scenarios; explicit production warning and teardown caveat | Not a universal verifier; Windows is not officially supported in the checked README |
| [Neo4j GDS betweenness centrality](https://neo4j.com/docs/graph-data-science/current/algorithms/betweenness-centrality/) | Betweenness measures how often a node lies on shortest paths and has material compute/memory cost | It does not directly measure vulnerability or exploitability |
| [Principal Mapper repository](https://github.com/nccgroup/PMapper) | Models AWS IAM users/roles as a directed graph and analyzes privilege-escalation/alternate paths | Useful baseline; inspect its authorization coverage and maintenance status before reuse |
| [pathfinding.cloud repository](https://github.com/DataDog/pathfinding.cloud) | Structured community library of AWS IAM escalation paths, prerequisites, detections, and mitigations | Community-maintained knowledge; validate selected paths against AWS behavior |

## Primary research sources checked

| Source | Verified claim | Caveat |
|---|---|---|
| [LLMCloudHunter preprint](https://arxiv.org/abs/2407.05194) | Uses LLMs to create generic-signature detection-rule candidates from textual and visual cloud OSCTI; reports extraction/compilation metrics on 12 annotated reports | Verify final publication venue/bibliography from ACM proceedings before submission; output is not structural IAM graph rules |
| [USENIX Security 2025 SoK](https://www.usenix.org/conference/usenixsecurity25/presentation/buechel) | Reviews 40+ TTP-extraction papers, reports comparability/data problems, a performance limit, and strong traditional NLP baselines | Does not prove that every new hybrid approach will fail |

## Claim checks from the raw chats

| Claim | Verdict | Correction/qualification |
|---|---|---|
| MITRE ATT&CK has official STIX/TAXII access | **True** | Use official data endpoints and pin the version |
| AWS Threat Technique Catalog exists and is AWS/IAM relevant | **True** | AWS CIRT describes observed AWS-specific techniques, detections, and mitigations |
| OWASP Cloud is one equivalent live CTI feed | **False/misleading** | The selected OWASP project is guidance and needs curated/versioned ingestion |
| Policy Simulator can drop denied paths and prove allowed ones | **Mostly true / misleading** | Deny is useful within supplied context; allow is not live exploit proof and unsupported controls can make results incomplete |
| CloudGoat can execute and confirm any discovered path “100%” | **False** | It has curated scenarios; only explicitly mapped paths can be tested, and results remain scenario-specific |
| Betweenness centrality identifies security chokepoints | **Unverifiable as a general claim** | It identifies shortest-path brokerage; security value must be tested on the project's graph/tasks |
| PMapper models AWS IAM principals as a graph for escalation/path analysis | **True** | Its exact coverage and local simulation limitations require direct evaluation |
| LLMCloudHunter generates structural IAM misconfiguration rules | **False** | It generates generic-signature detection-rule candidates from cloud OSCTI |
| The reported parser prototype is complete | **Unverifiable** | No code or test output is present in this folder |
| No prior system combines the full proposed pipeline | **Unverifiable** | Requires a systematic literature and tool search with explicit criteria |

## Raw local evidence

The adjacent files named `ChatGPT-*.md` are the historical conversation exports used to reconstruct project intent. They are not cited as proof of external facts. The largest export contains the supplied synopsis/project-report text and earlier generated documentation drafts; other exports cover source selection, engine division, an alleged parser prototype, environment errors, and tentative Engine 2/3 contracts.

## Citation rule

For any report claim, cite the most direct publisher, official documentation, repository, dataset, or proceedings page. Search snippets and AI conversation summaries are discovery aids, not final references.

