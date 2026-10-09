"""Loopback analyst handoff for one paired observation report.

The reviewer alias is operator configuration, not authentication. Export is
redacted and is bound to the exact report digest. Local operator review is
not authenticated authority and not exploit proof.
"""

from typing import Literal

from pydantic import ConfigDict, Field

from fyp_iam.contracts.models import ContractModel
from fyp_iam.engine2.paired_observation import PairedObservationReport, paired_report_digest

AUTHORITY_LIMIT: Literal[
    "Local operator review is not authenticated authority and not exploit proof."
] = "Local operator review is not authenticated authority and not exploit proof."
HandoffDecision = Literal["accept", "reject", "needs-context"]


class HandoffReviewRejected(Exception):
    """Fixed reason a review or export cannot proceed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class HandoffReviewReceipt(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    decision: HandoffDecision
    reviewer_alias: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")


class RedactedHandoffExport(ContractModel):
    """The only JSON an analyst may take away from loopback review."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    rule_version: int = Field(ge=1, le=1000)
    reviewer_alias: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    observed_facts: tuple[str, ...]
    inferences: tuple[str, ...]
    unknowns: tuple[str, ...]
    authority_limit: Literal[
        "Local operator review is not authenticated authority and not exploit proof."
    ] = AUTHORITY_LIMIT


class _StoredReview:
    def __init__(self, receipt: HandoffReviewReceipt, export: RedactedHandoffExport) -> None:
        self.receipt = receipt
        self.export = export


class HandoffReviewLedger:
    """In-memory decisions. A different digest cannot be exported."""

    def __init__(self) -> None:
        self._rows: dict[str, _StoredReview] = {}

    def record(
        self,
        report: PairedObservationReport,
        decision: HandoffDecision,
        reviewer_alias: str,
    ) -> HandoffReviewReceipt:
        if report.report_digest != paired_report_digest(report):
            raise HandoffReviewRejected("report_digest_rejected")
        receipt = HandoffReviewReceipt(
            report_digest=report.report_digest,
            decision=decision,
            reviewer_alias=reviewer_alias,
        )
        existing = self._rows.get(report.report_digest)
        if existing is not None and existing.receipt.decision != decision:
            raise HandoffReviewRejected("report_digest_rejected")
        if existing is None:
            self._rows[report.report_digest] = _StoredReview(
                receipt, _export(report, reviewer_alias)
            )
        return receipt

    def export(self, report_digest: str) -> RedactedHandoffExport:
        stored = self._rows.get(report_digest)
        if stored is None or stored.receipt.report_digest != report_digest:
            raise HandoffReviewRejected("report_digest_rejected")
        return stored.export


def _export(report: PairedObservationReport, reviewer_alias: str) -> RedactedHandoffExport:
    facts: list[str] = []
    inferences: list[str] = []
    unknowns: list[str] = []
    for identity in (report.first, report.second):
        _append_new(facts, identity.observed_facts)
        _append_new(inferences, identity.inferences)
        _append_new(unknowns, identity.unknowns)
    return RedactedHandoffExport(
        snapshot_digest=report.snapshot_digest,
        rule_version=report.rule_version,
        reviewer_alias=reviewer_alias,
        observed_facts=tuple(facts),
        inferences=tuple(inferences),
        unknowns=tuple(unknowns),
    )


def _append_new(destination: list[str], lines: tuple[str, ...]) -> None:
    for line in lines:
        if line not in destination:
            destination.append(line)
