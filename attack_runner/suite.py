from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from detectors.engine import DetectionResult, DetectionStatus, Detector
from mcp_servers.filesystem_server.models import FileServiceConfig

from .audit_events import build_file_access_event
from .audit_match import AuditedFileRead, match_audit_records
from .audit_reader import load_audit_records
from .batch import run_file_batch
from .cases import FileReadTestCase, validate_test_cases
from .expectations import CaseVerdict, VerdictStatus, evaluate_file_read


@dataclass(frozen=True)
class FileReadTestResult:
    audited: AuditedFileRead
    findings: tuple[DetectionResult, ...]
    verdict: CaseVerdict

# statistical results
@dataclass(frozen=True)
class SuiteSummary:
    total: int
    passed: int
    failed: int
    detection_errors: int

    @property
    def successful(self) -> bool:
        return (
            self.total > 0
            and self.failed == 0
            and self.detection_errors == 0
        )

def summarize_suite(
    results: Sequence[FileReadTestResult],
)-> SuiteSummary:
    snapshot = tuple(results)

    passed = sum(
        result.verdict.status is VerdictStatus.PASSED
        for result in snapshot
    )

    failed = sum(
        result.verdict.status is VerdictStatus.FAILED
        for result in snapshot
    )

    detection_errors = sum(
        finding.status is DetectionStatus.ERROR
        for result in snapshot
        for finding in result.findings
    )

    return SuiteSummary(
        total=len(snapshot),
        passed=passed,
        failed=failed,
        detection_errors=detection_errors,
    )


async def run_file_suite(
    cases: Sequence[FileReadTestCase],
    config: FileServiceConfig,
    detector: Detector,
    *,
    audit_path: Path,
)-> tuple[FileReadTestResult, ...]:
    '''
    batch processing all cases
    '''
    validated = validate_test_cases(cases)

    expectations_by_id = {
        item.case.case_id: item.expectation
        for item in validated
    }

    results = await run_file_batch(
        tuple(item.case for item in validated),
        config,
        audit_path=audit_path,
    )

    records = load_audit_records(audit_path)
    audited_results = match_audit_records(results, records)

    suite_results: list[FileReadTestResult] = []

    for audited in audited_results:
        event = build_file_access_event(audited)
        findings = detector.detect(event)

        expectation = expectations_by_id[audited.result.case_id]

        verdict = evaluate_file_read(
            audited,
            findings,
            expectation,
        )

        suite_results.append(
            FileReadTestResult(
                audited=audited,
                findings=findings,
                verdict=verdict,
            )
        )

    return tuple(suite_results)
