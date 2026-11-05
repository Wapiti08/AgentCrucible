from dataclasses import dataclass

from .audit_reader import FileReadAuditEntry
from .batch import FileReadCaseResult


class AuditMatchError(RuntimeError):
    """Raised when audit records do not match batch results."""


@dataclass(frozen=True)
class AuditedFileRead:
    result: FileReadCaseResult
    audit: FileReadAuditEntry

def match_audit_records(
    results: tuple[FileReadCaseResult, ...],
    records: tuple[FileReadAuditEntry, ...],
) -> tuple[AuditedFileRead, ...]:
    records_by_id: dict[str, FileReadAuditEntry] = {}

    for record in records:
        if record.request_id in records_by_id:
            raise AuditMatchError("Duplicate audit request_id.")

        records_by_id[record.request_id] = record

    matched: list[AuditedFileRead] = []
    seen_result_ids: set[str] = set()

    for result in results:
        response = result.response
        request_id = response.request_id

        if request_id in seen_result_ids:
            raise AuditMatchError("Duplicate result request_id.")

        seen_result_ids.add(request_id)
        # core matching logic
        record = records_by_id.get(request_id)
        if record is None:
            raise AuditMatchError(
                "A batch result has no matching audit record."
            )

        if (
            record.original_path != result.path
            or record.policy_decision != response.policy_decision
            or record.execution_status != response.execution_status
            or record.reason != response.reason
        ):
            raise AuditMatchError(
                "An audit record disagrees with its batch result."
            )

        matched.append(
            AuditedFileRead(result=result, audit=record)
        )

    if records_by_id.keys() != seen_result_ids:
        raise AuditMatchError(
            "The audit file contains unmatched records."
        )

    return tuple(matched)
