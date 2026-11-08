"""Generate machine-readable JSON security reports."""

from attack_runner.suite import FileReadTestResult, summarize_suite
from collections.abc import Sequence
import json
from pathlib import Path

class ReportWriteError(RuntimeError):
    """Raised when a report cannot be serialized or saved."""

def serialize_case_result(
    result: FileReadTestResult,
) -> dict[str, object]:
    response = result.audited.result.response
    expected = result.expectation
    verdict = result.verdict

    return {
        "case_id": verdict.case_id,
        "request_id": verdict.request_id,
        "path": result.audited.result.path,
        "expected": {
            "policy_decision": expected.policy_decision.value,
            "execution_status": expected.execution_status.value,
            "rule_id": expected.rule_id,
            "detection_status": expected.detection_status.value,
        },
        "actual": {
            "policy_decision": response.policy_decision,
            "execution_status": response.execution_status,
            "reason": response.reason,
            "returned_bytes": response.returned_bytes,
            "truncated": response.truncated,
        },
        "findings": [
            {
                "event_id": finding.event_id,
                "rule_id": finding.rule_id,
                "status": finding.status.value,
                "reason": finding.reason,
            }
            for finding in result.findings
        ],
        "verdict": {
            "status": verdict.status.value,
            "mismatches": list(verdict.mismatches),
        },
    }


def build_suite_report(
    results: Sequence[FileReadTestResult],
    *,
    run_id: str,
) -> dict[str, object]:
    if not isinstance(run_id, str):
        raise TypeError("run_id must be a string.")

    if not run_id.strip() or run_id != run_id.strip():
        raise ValueError(
            "run_id must be non-empty without surrounding whitespace."
        )

    snapshot = tuple(results)
    summary = summarize_suite(snapshot)

    return {
        "schema_version": 1,
        "run_id": run_id,
        "run_status": "completed",
        "summary": {
            "total": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "detection_errors": summary.detection_errors,
            "successful": summary.successful,
        },
        "cases": [
            serialize_case_result(result)
            for result in snapshot
        ],
    }


def write_suite_report(
    path: Path,
    report: dict[str, object],
) -> None:
    try:
        content = json.dumps(
            report,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
        ) + "\n"
    except (TypeError, ValueError) as exc:
        raise ReportWriteError(
            "Unable to serialize the report."
        ) from exc

    try:
        with path.open(
            mode="x",
            encoding="utf-8",
            newline="\n",
        ) as report_file:
            written = report_file.write(content)

            if written != len(content):
                raise OSError("Incomplete report write.")

    except OSError as exc:
        raise ReportWriteError(
            "Unable to save the report."
        ) from exc
