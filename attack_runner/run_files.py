"""
CLI interface to run batch of real files

how to run:
    uv run python -m attack_runner.run_files \
    --workspace /fixtures \
    --allowed-root public \
    --max-read-bytes 65536 \
    --path public/readme.txt \
    --path public/../secret/token.txt

"""
import asyncio
import tempfile
from pathlib import Path
import json
import sys
import argparse
from collections.abc import Sequence
from detectors.engine import Detector, DetectionStatus
from detectors.rules.fs_path_traversal import FilePathOutsideScopeRule

from .audit_events import build_file_access_event
from mcp_servers.filesystem_server.models import FileServiceConfig
from .batch import (
    BatchAbortedError,
    FileReadCase,
    FileReadCaseResult,
    run_file_batch,
    validate_cases,
)
from .audit_reader import AuditReadError, load_audit_records
from .audit_match import AuditMatchError, match_audit_records


def parse_inputs(
    argv: Sequence[str] | None = None,
) -> tuple[FileServiceConfig, tuple[FileReadCase, ...]]:
    parser = argparse.ArgumentParser(
        description="Run file-read cases against the filesystem MCP server.",
    )

    parser.add_argument(
        "--workspace",
        required=True,
        help="Absolute workspace path in the Linux environment.",
    )
    parser.add_argument(
        "--allowed-root",
        action="append",
        default=[],
        help="Authorized directory; may be repeated.",
    )
    parser.add_argument(
        "--max-read-bytes",
        type=int,
        default=65536,
    )
    parser.add_argument(
        "--path",
        action="append",
        required=True,
        help="File path to test; may be repeated.",
    )

    args = parser.parse_args(argv)

    try:
        config = FileServiceConfig(
            workspace_root=args.workspace,
            authorized_roots=tuple(args.allowed_root),
            max_read_bytes=args.max_read_bytes,
        )

        cases = validate_cases(
            tuple(
                FileReadCase(
                    case_id=f"case-{index}",
                    path=path,
                )
                for index, path in enumerate(args.path, start=1)
            )
        )
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))

    return config, cases


def print_results(results: Sequence[FileReadCaseResult]) -> None:
    for result in results:
        response = result.response

        record = {
            "case_id": result.case_id,
            "path": result.path,
            "request_id": response.request_id,
            "policy_decision": response.policy_decision,
            "execution_status": response.execution_status,
            "reason": response.reason,
            "returned_bytes": response.returned_bytes,
            "truncated": response.truncated,
        }

        print(json.dumps(record, ensure_ascii=True))


def create_audit_path(config: FileServiceConfig) -> Path:
    workspace = Path(config.workspace_root).resolve()
    audit_parent = Path(tempfile.gettempdir()).resolve(strict=True)

    if audit_parent.is_relative_to(workspace):
        raise ValueError(
            "The temporary audit directory would be inside the workspace."
        )

    audit_directory = Path(
        tempfile.mkdtemp(
            prefix="agentcrucible-audit-",
            dir=audit_parent,
        )
    )

    return audit_directory / "events.jsonl"


def main(argv: Sequence[str] | None = None) -> int:
    config, cases = parse_inputs(argv)

    try:
        audit_path = create_audit_path(config)
    except (OSError, ValueError):
        print(
            json.dumps({"error": "audit_setup_failed"}),
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {"audit_file": str(audit_path)},
            ensure_ascii=True,
        ),
        file=sys.stderr,
    )

    try:
        results = asyncio.run(
                    run_file_batch(
                        cases,
                        config,
                        audit_path=audit_path,
                    )
                )

    except BatchAbortedError as exc:
        print_results(exc.completed_results)

        error = {
            "error": "batch_aborted",
            "phase": exc.phase,
            "failed_case_id": (
                exc.failed_case.case_id
                if exc.failed_case is not None
                else None
            ),
            "completed_count": len(exc.completed_results),
        }

        print(json.dumps(error, ensure_ascii=True), file=sys.stderr)
        return 1

    print_results(results)

    # load audit files and check matched records
    try:
        records = load_audit_records(audit_path)
        audited_results = match_audit_records(results, records)
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
        return 1

    # use detector to check matched audited results
    detector = Detector(
        rules=(FilePathOutsideScopeRule(),),
    )
    detection_failed = False

    for audited in audited_results:
        event = build_file_access_event(audited)
        findings = detector.detect(event)

        for finding in findings:
            record = {
                "record_type": "detector.finding",
                "case_id": audited.result.case_id,
                "request_id": audited.result.response.request_id,
                "event_id": finding.event_id,
                "rule_id": finding.rule_id,
                "status": finding.status.value,
                "reason": finding.reason,
            }
            print(json.dumps(record, ensure_ascii=True))

            if finding.status is DetectionStatus.ERROR:
                detection_failed = True

    if detection_failed:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
