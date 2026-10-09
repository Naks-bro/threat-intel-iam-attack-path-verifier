# AWS usage guardrails

Implemented locally on 2026-10-03. These are conservative project limits, not
measurements of AWS service quotas, remaining credits, or Free Tier eligibility.

## Enforced preflight controls

- Reserve each CLI invocation before transport: at most 12 per rolling minute
  and 120 per rolling 24 hours, across processes and profiles in this checkout.
- Persist counters atomically in the gitignored `.aws-safety/` directory, using
  a separate process lock. Busy locks, invalid state, missing initialized state,
  unavailable storage, and backward clock movement refuse new calls.
- Transport failures introduce increasing cooldowns, starting at 60 seconds and
  capped at 15 minutes. There is no automatic retry loop. Failed or abandoned
  reservations still consume the allowance; successful calls do not reset it.
- Set `FYP_AWS_STOP=1` to refuse calls in processes inheriting that environment.
  The persistent stop switch below covers this checkout's guarded processes.
- Preserve the existing three-operation allowlist, root/account checks, bounded
  IAM probes, timeouts, redacted results, and one configured CLI request attempt.

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m fyp_iam.engine2.aws_guard stop
.\.venv\Scripts\python.exe -m fyp_iam.engine2.aws_guard resume
```

Resuming does not clear counters or cooldowns. Stop prevents future reservations;
it does not cancel an already running command. Do not delete or edit guard state
to bypass limits. The ledger contains timestamps and counters, not credentials.

## Limits of this protection

Only preflight calls routed through this guard are covered. Direct AWS CLI use,
other checkouts, machines, SDK clients, and MCPO tools are not automatically
covered. Profile authentication can make additional requests beyond the metered
CLI invocation. This cooperative local control is not tamper-proof against an
operator or agent with unrestricted shell/file access.

Read-only does not universally mean free. A request allowance is not a dollar
cap, and neither it nor AWS service quotas prevent charges from existing resources.
No paid service, resource provisioning, billing API, or account permission change
was enabled by this safeguard implementation.

## Account-side setup still pending

Before live collection, confirm a dedicated non-root identity and its effective
least-privilege permissions, intended account, applicable plan/credits and expiry,
current usage, and service-specific allowances. Configure appropriate Free Tier
usage notifications and a cost budget with actual/forecast alerts through the
trusted AWS console. The owner must supply a monthly USD threshold and recipient.

Budget alerts are not a hard spending cap: AWS documents delays between resource
usage, billing updates and notifications. Keep provisioning/write tools disabled
by default and authorize any isolated write lab separately with cleanup controls.
MCPO must have its tool inventory, authentication, target identity and exposure
reviewed before use; no connector-wide limiter is claimed here.

No live AWS or billing check was performed for this implementation. A safe profile,
budget threshold/email, and reachable reviewed MCPO endpoint remain needed.

## Verification

Offline tests cover rolling windows, persistent stop/resume, cooldowns, invalid
state, clock rollback, refusal before transport, failure propagation, and six real
local processes sharing one allowance. Tests use temporary state and fake AWS
transport, not account credentials. Cross-process behavior was tested on Windows;
the POSIX locking branch has not been exercised on this machine.

Primary references:
[AWS CLI retries](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-retries.html),
[AWS Budgets best practices](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-best-practices.html),
and [Free Tier usage tracking](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/tracking-free-tier-usage.html).
