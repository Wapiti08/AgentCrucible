from dataclasses import dataclass
from pathlib import Path

from detectors.engine import DetectionResult, Detector

from attack_runner.execution.agent_execution import AgentFileReadRecord
from attack_runner.file_cases import FileReadCaseResult
from attack_runner.evidence.audit_reader import load_audit_records
from attack_runner.evidence.audit_match import (
    AuditedFileRead,
    match_audit_records,
)
from attack_runner.evidence.audit_events import build_file_access_event


@dataclass(frozen=True)
class AgentReadFinding:
    audited: AuditedFileRead
    findings: tuple[DetectionResult, ...]


def detect_agent_reads(
    records: tuple[AgentFileReadRecord, ...],
    *,
    audit_path: Path,
    detector: Detector,
) -> tuple[AgentReadFinding, ...]:
    results = tuple(
        FileReadCaseResult(
            case_id=record.call.call_id,
            path=record.call.path,
            response=record.response,
        )
        for record in records
    )

    audit_records = load_audit_records(audit_path)
    audited_reads = match_audit_records(results, audit_records)

    return tuple(
        AgentReadFinding(
            audited=audited,
            findings=detector.detect(
                build_file_access_event(audited)
            ),
        )
        for audited in audited_reads
    )
