from uuid import uuid4

from reports.json_report import (
    ReportWriteError,
    build_suite_report,
    write_suite_report,
)

import argparse
from collections.abc import Sequence
from pathlib import Path
import json

import asyncio
import sys

from detectors.engine import Detector
from detectors.rules.fs_path_traversal import FilePathOutsideScopeRule

from .audit_match import AuditMatchError
from .audit_reader import AuditReadError
from .batch import BatchAbortedError
from .runtime_paths import create_audit_path
from .suite import (
    FileReadTestResult,
    SuiteSummary,
    run_file_suite,
    summarize_suite,
)

from mcp_servers.filesystem_server.models import FileServiceConfig

from .case_loader import CaseLoadError, load_case_file
from .cases import FileReadTestCase


def parse_inputs(
    argv: Sequence[str] | None = None,
) -> tuple[
        FileServiceConfig,
        tuple[FileReadTestCase, ...],
        Path | None,
    ]:
    parser = argparse.ArgumentParser(
        description="Run filesystem security regression cases.",
    )
    parser.add_argument(
        "--report-file",
        type=Path,
        help="Save a JSON report to a new file.",
    )

    parser.add_argument(
        "--case-file",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--workspace",
        required=True,
    )
    parser.add_argument(
        "--allowed-root",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--max-read-bytes",
        type=int,
        default=65536,
    )

    args = parser.parse_args(argv)

    try:
        config = FileServiceConfig(
            workspace_root=args.workspace,
            authorized_roots=tuple(args.allowed_root),
            max_read_bytes=args.max_read_bytes,
        )
        cases = load_case_file(args.case_file)
    except (TypeError, ValueError, CaseLoadError) as exc:
        parser.error(str(exc))

    return config, cases, args.report_file


def print_suite_results(
    results: Sequence[FileReadTestResult],
    summary: SuiteSummary,
) -> None:
    for result in results:
        response = result.audited.result.response
        verdict = result.verdict

        record = {
            "record_type": "case.verdict",
            "case_id": verdict.case_id,
            "request_id": verdict.request_id,
            "status": verdict.status.value,
            "mismatches": list(verdict.mismatches),
            "actual": {
                "policy_decision": response.policy_decision,
                "execution_status": response.execution_status,
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
        }

        print(json.dumps(record, ensure_ascii=True))

    summary_record = {
        "record_type": "suite.summary",
        "total": summary.total,
        "passed": summary.passed,
        "failed": summary.failed,
        "detection_errors": summary.detection_errors,
        "successful": summary.successful,
    }

    print(json.dumps(summary_record, ensure_ascii=True))


def main(argv: Sequence[str] | None = None) -> int:
    config, cases, report_path = parse_inputs(argv)
    run_id = str(uuid4())

    detector = Detector(
        rules=(FilePathOutsideScopeRule(),),
    )

    try:
        audit_path = create_audit_path(config)
    except (OSError, ValueError):
        print(
            json.dumps({"error": "audit_setup_failed"}),
            file=sys.stderr,
        )
        return 3

    print(
        json.dumps(
            {
                "run_id": run_id,
                "audit_file": str(audit_path),
            },            ensure_ascii=True,
        ),
        file=sys.stderr,
    )

    try:
        results = asyncio.run(
            run_file_suite(
                cases,
                config,
                detector,
                audit_path=audit_path,
            )
        )
    except BatchAbortedError as exc:
        print(
            json.dumps(
                {
                    "error": "batch_aborted",
                    "phase": exc.phase,
                    "failed_case_id": (
                        exc.failed_case.case_id
                        if exc.failed_case is not None
                        else None
                    ),
                    "completed_count": len(exc.completed_results),
                },
                ensure_ascii=True,
            ),
            file=sys.stderr,
        )
        return 3
    except (AuditReadError, AuditMatchError) as exc:
        print(
            json.dumps(
                {
                    "error": "audit_validation_failed",
                    "reason": str(exc),
                },
                ensure_ascii=True,
            ),
            file=sys.stderr,
        )
        return 3

    summary = summarize_suite(results)
    print_suite_results(results, summary)

    if report_path is not None:
        report = build_suite_report(
            results,
            run_id=run_id,
        )

        try:
            write_suite_report(report_path, report)
        except ReportWriteError as exc:
            print(
                json.dumps(
                    {
                        "error": "report_write_failed",
                        "run_id": run_id,
                        "reason": str(exc),
                    },
                    ensure_ascii=True,
                ),
                file=sys.stderr,
            )
            return 3

    if summary.detection_errors:
        return 3

    return 0 if summary.successful else 1


if __name__ == "__main__":
    raise SystemExit(main())
