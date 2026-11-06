from dataclasses import dataclass
from enum import Enum
from detectors.engine import DetectionStatus, DetectionResult
from mcp_servers.filesystem_server.models import (
    ExecutionStatus,
    PolicyDecision,
)
from .audit_match import AuditedFileRead


class VerdictStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"

@dataclass(frozen=True)
class CaseVerdict:
    case_id: str
    request_id: str
    status: VerdictStatus
    # remain failure reason
    mismatches: tuple[str, ...]


@dataclass(frozen=True)
class FileReadExpectation:
    policy_decision: PolicyDecision
    execution_status: ExecutionStatus
    rule_id: str
    detection_status: DetectionStatus

    def __post_init__(self) -> None:
        if not isinstance(self.policy_decision, PolicyDecision):
            raise TypeError(
                "policy_decision must be a PolicyDecision."
            )

        if not isinstance(self.execution_status, ExecutionStatus):
            raise TypeError(
                "execution_status must be an ExecutionStatus."
            )

        if not isinstance(self.detection_status, DetectionStatus):
            raise TypeError(
                "detection_status must be a DetectionStatus."
            )

        if not isinstance(self.rule_id, str):
            raise TypeError("rule_id must be a string.")

        if not self.rule_id.strip():
            raise ValueError("rule_id must not be empty.")

        if self.rule_id != self.rule_id.strip():
            raise ValueError(
                "rule_id must not have surrounding whitespace."
            )


# accepted matched results, detected results and expectations for comparison
def evaluate_file_read(
    audited: AuditedFileRead,
    findings: tuple[DetectionResult, ...],
    expectation: FileReadExpectation,
) -> CaseVerdict:
    """
    single case check for expectation
    """
    result = audited.result
    response = result.response
    mismatches: list[str] = []

    # define specific mismatch cases
    if response.policy_decision != expectation.policy_decision.value:
        mismatches.append(
            "Policy decision: "
            f"expected {expectation.policy_decision.value}, "
            f"got {response.policy_decision}."
        )

    if response.execution_status != expectation.execution_status.value:
        mismatches.append(
            "Execution status: "
            f"expected {expectation.execution_status.value}, "
            f"got {response.execution_status}."
        )

    expected_event_id = f"{response.request_id}:filesystem.read"

    if any(
        finding.event_id != expected_event_id
        for finding in findings
    ):
        mismatches.append(
            "Detection results contain an unrelated event."
        )

    # define matched conditions
    matching_findings = [
        finding
        for finding in findings
        if finding.event_id == expected_event_id
        and finding.rule_id == expectation.rule_id
    ]

    # right case is matching one specific condition
    if not matching_findings:
        mismatches.append(
            f"Expected rule {expectation.rule_id} returned no result."
        )
    elif len(matching_findings) > 1:
        mismatches.append(
            f"Expected rule {expectation.rule_id} returned duplicate results."
        )
    else:
        actual_status = matching_findings[0].status

        if actual_status != expectation.detection_status:
            mismatches.append(
                "Detection status: "
                f"expected {expectation.detection_status.value}, "
                f"got {actual_status.value}."
            )

    return CaseVerdict(
        case_id=result.case_id,
        request_id=response.request_id,
        status=(
            VerdictStatus.FAILED
            if mismatches
            else VerdictStatus.PASSED
        ),
        mismatches=tuple(mismatches),
    )
