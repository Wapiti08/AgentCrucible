from dataclasses import dataclass
from typing import Literal
import json
from .models import ExecutionStatus, PolicyDecision, ReadResult
from pathlib import Path
from types import TracebackType
from typing import Self

@dataclass(frozen=True)
class FileReadAuditRecord:
    schema_version: Literal[1]
    request_id: str
    original_path: str
    resolved_path: str | None
    authorized_roots: tuple[str, ...] | None
    policy_decision: PolicyDecision
    execution_status: ExecutionStatus
    reason: str


def build_audit_record(result: ReadResult) -> FileReadAuditRecord:
    return FileReadAuditRecord(
        schema_version=1,
        request_id=result.request_id,
        original_path=result.original_path,
        resolved_path=result.resolved_path,
        authorized_roots=result.authorized_roots,
        policy_decision=result.policy_decision,
        execution_status=result.execution_status,
        reason=result.reason,
    )


def serialize_audit_record(record: FileReadAuditRecord) -> str:
    payload = {
        "schema_version": record.schema_version,
        "request_id": record.request_id,
        "original_path": record.original_path,
        "resolved_path": record.resolved_path,
        "authorized_roots": (
            list(record.authorized_roots)
            if record.authorized_roots is not None
            else None
        ),
        "policy_decision": record.policy_decision.value,
        "execution_status": record.execution_status.value,
        "reason": record.reason,
    }

    return json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
    ) + "\n"


# define the creation and closure of the writer
class AuditWriteError(RuntimeError):
    """The audit record could not be stored reliably."""


class JsonlAuditWriter:
    def __init__(self, path: Path) -> None:
        self._failed = False

        try:
            self._stream = path.open(
                # exclusive creation model, failed if exists
                mode="x",
                encoding="utf-8",
                newline="\n",
            )
        except OSError as exc:
            raise AuditWriteError(
                    "Unable to create the audit file."
                ) from exc

    def write(self, record: FileReadAuditRecord) -> None:

        self.ensure_available()

        try:
            line = serialize_audit_record(record)

            written = self._stream.write(line)
            if written != len(line):
                raise OSError("Incomplete audit record write.")

            self._stream.flush()

        except Exception as exc:
            self._failed = True
            raise AuditWriteError(
                "Unable to write the audit record."
            ) from exc

    def ensure_available(self) -> None:
        if self._stream.closed or self._failed:
            raise AuditWriteError("The audit writer is unavailable.")

    def close(self) -> None:
        if self._stream.closed:
            return

        try:
            self._stream.close()
        except OSError as exc:
            self._failed = True
            raise AuditWriteError(
                "Unable to close the audit file."
            ) from exc

    def __enter__(self) -> Self:
        self.ensure_available()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()