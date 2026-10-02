# Architecture

## Two research stages, four engineering engines

The apparent conflict in the chats is resolved as follows:

- **Research Stage 1 — Rule curation:** Engine 1.
- **Research Stage 2 — Detection, verification, and presentation:** Engines 2, 3, and 4.

The four-engine split is an ownership and parallel-development strategy, not a change to the academic two-stage framing.

```text
Official/curated CTI sources
          |
          v
+-------------------------------+
| Engine 1: CTI -> IAM rules    |
| ingest, normalize, interpret, |
| validate, explain, approve    |
+---------------+---------------+
                | ApprovedRule[]
                |
AWS account     v
(read-only) +-------------------------------+
        ---->| Engine 2: IAM graph          |
             | collect, normalize, resolve, |
             | snapshot, validate           |
             +---------------+---------------+
                             | IAMGraphSnapshot
ApprovedRule[] --------------+
                             v
             +-------------------------------+
             | Engine 3: path verification  |
             | match, traverse, simulate,    |
             | optional mapped sandbox test  |
             +---------------+---------------+
                             | VerificationResult[]
                             v
             +-------------------------------+
             | Engine 4: decision support   |
             | prioritize, explain, display,|
             | evaluate, export             |
             +-------------------------------+
```

## Shared platform

The tentative shared stack is:

| Concern | Baseline | Status |
|---|---|---|
| Language | Python | Accepted direction; version not frozen |
| API and validation | FastAPI + Pydantic | Proposed |
| Relational records/audit | PostgreSQL | Proposed |
| IAM graph | Neo4j | Accepted direction, implementation unverified |
| Graph analytics | Neo4j GDS | Optional; use only for defined experiments |
| Background jobs | Redis-backed worker | Deferred until synchronous slice works |
| UI | React-based frontend with graph visualization | Proposed; framework/library not frozen |
| Local orchestration | Docker Compose | Proposed |

Redis, GDS, an LLM provider, and a complex frontend are not required to prove the first vertical slice. Add them when a measured need exists.

## Responsibility boundaries

| Capability | E1 | E2 | E3 | E4 |
|---|:---:|:---:|:---:|:---:|
| CTI acquisition/normalization | Owns |  |  |  |
| Candidate rule generation | Owns |  |  |  |
| Rule approval/audit | Owns |  | Consumes | Displays |
| AWS read-only collection |  | Owns |  |  |
| IAM semantic model/graph |  | Owns | Consumes | Displays |
| Rule matching/path discovery |  |  | Owns | Consumes |
| Policy simulation |  |  | Owns | Displays |
| Sandbox mapping/execution |  |  | Owns | Displays |
| Risk ranking/explanation |  |  | Supplies evidence | Owns |
| Research metrics/UI/export | Supplies data | Supplies data | Supplies data | Owns |

## Data-flow principles

- Engines exchange immutable, versioned records; they do not reach into each other's internal tables.
- Raw source text and AWS policy documents are stored or referenced separately from normalized records.
- Every derived artifact links to its inputs through stable IDs and hashes.
- Reprocessing creates a new version/run; it does not silently mutate historical evidence.
- Unknown, unsupported, and inconclusive are first-class states.

## Trust boundaries

1. **External CTI:** untrusted input; size-limit, parse, sanitize, and retain provenance.
2. **LLM:** non-deterministic suggestion service; schema-constrain, validate, and require human approval.
3. **Live AWS:** sensitive, read-only target; use least privilege and redact account-specific data.
4. **Sandbox:** intentionally vulnerable and potentially costly; isolate, authorize, budget, and destroy.
5. **Browser/UI:** untrusted rendering boundary; escape source text and never render generated HTML unsafely.

