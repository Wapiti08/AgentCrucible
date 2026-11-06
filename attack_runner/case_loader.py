import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from detectors.engine import DetectionStatus
from mcp_servers.filesystem_server.models import (
    ExecutionStatus,
    PolicyDecision,
)

from .batch import FileReadCase
from .cases import FileReadTestCase, validate_test_cases
from .expectations import FileReadExpectation

class CaseLoadError(RuntimeError):
    """Raised when a case file cannot be loaded reliably."""


class _InputModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
    )


class ExpectationInput(_InputModel):
    policy_decision: Literal[
        "allowed", "blocked", "not_evaluated", "error"
    ]
    execution_status: Literal[
        "succeeded", "failed", "not_started"
    ]
    rule_id: str = Field(min_length=1)
    detection_status: Literal[
        "detected", "not_detected", "not_evaluated", "error"
    ]


class FileReadCaseInput(_InputModel):
    case_id: str = Field(min_length=1)
    path: str
    expectation: ExpectationInput


class CaseFileInput(_InputModel):
    schema_version: Literal[1]
    cases: list[FileReadCaseInput] = Field(min_length=1)

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_schema_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError(
                "schema_version must be an integer."
            )
        return value

def _build_test_cases(
    document: CaseFileInput,
) -> tuple[FileReadTestCase, ...]:
    cases: list[FileReadTestCase] = []

    for index, item in enumerate(document.cases, start=1):
        expected = item.expectation

        try:
            expectation = FileReadExpectation(
                policy_decision=PolicyDecision(
                    expected.policy_decision
                ),
                execution_status=ExecutionStatus(
                    expected.execution_status
                ),
                rule_id=expected.rule_id,
                detection_status=DetectionStatus(
                    expected.detection_status
                ),
            )
        except (TypeError, ValueError) as exc:
            raise CaseLoadError(
                f"Invalid expectation in case {index}: {exc}"
            ) from exc

        cases.append(
            FileReadTestCase(
                case=FileReadCase(
                    case_id=item.case_id,
                    path=item.path,
                ),
                expectation=expectation,
            )
        )

    try:
        return validate_test_cases(cases)
    except (TypeError, ValueError) as exc:
        raise CaseLoadError(
            f"Invalid case collection: {exc}"
        ) from exc


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


def load_case_file(
    path: Path,
) -> tuple[FileReadTestCase, ...]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CaseLoadError(
            "Unable to read the case file."
        ) from exc

    try:
        raw_document = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
    except ValueError as exc:
        raise CaseLoadError(
            f"Invalid case-file JSON: {exc}"
        ) from exc

    try:
        document = CaseFileInput.model_validate(raw_document)
    except ValueError as exc:
        raise CaseLoadError(
            f"Invalid case-file structure: {exc}"
        ) from exc

    return _build_test_cases(document)
