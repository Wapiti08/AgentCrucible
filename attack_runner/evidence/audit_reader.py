import json
from pathlib import Path
from typing import Literal, Self
from pydantic import BaseModel, ConfigDict, Field, model_validator


class AuditReadError(RuntimeError):
    """Raised when the audit file cannot be loaded reliably."""

class FileReadAuditEntry(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
    )

    schema_version: Literal[1]
    request_id: str = Field(min_length=1)
    original_path: str
    resolved_path: str | None
    authorized_roots: list[str] | None

    policy_decision: Literal[
        "allowed",
        "blocked",
        "not_evaluated",
        "error",
    ]
    execution_status: Literal[
        "succeeded",
        "failed",
        "not_started",
    ]
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (
            self.policy_decision != "allowed"
            and self.execution_status != "not_started"
        ):
            raise ValueError(
                "A non-allowed policy decision requires "
                "execution_status='not_started'."
            )

        return self


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field.")
        result[key] = value

    return result

def _reject_nonstandard_constant(value: str) -> object:
    raise ValueError("Non-standard JSON constant.")


def load_audit_records(
    audit_path: Path,
) -> tuple[FileReadAuditEntry, ...]:
    records: list[FileReadAuditEntry] = []
    seen_request_ids: set[str] = set()

    try:
        with audit_path.open("r", encoding="utf-8") as audit_file:
            for line_number, line in enumerate(audit_file, start=1):
                if not line.endswith("\n"):
                    raise AuditReadError(
                        f"Audit line {line_number} is incomplete."
                    )

                if not line.strip():
                    raise AuditReadError(
                        f"Audit line {line_number} is empty."
                    )

                try:
                    raw_record = json.loads(
                        line,
                        object_pairs_hook=_reject_duplicate_keys,
                        parse_constant=_reject_nonstandard_constant,
                    )
                    record = FileReadAuditEntry.model_validate(
                        raw_record
                    )
                except ValueError as exc:
                    raise AuditReadError(
                        f"Invalid audit record at line {line_number}."
                    ) from exc

                if record.request_id in seen_request_ids:
                    raise AuditReadError(
                        f"Duplicate request_id at line {line_number}."
                    )

                seen_request_ids.add(record.request_id)
                records.append(record)

    except (OSError, UnicodeError) as exc:
        raise AuditReadError(
            "Unable to read the audit file."
        ) from exc

    return tuple(records)
