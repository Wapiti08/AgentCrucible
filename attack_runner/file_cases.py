"""Shared file-read case contracts and input validation."""
from dataclasses import dataclass
from collections.abc import Sequence
from attack_runner.transport.mcp_models import FileReadResponse

@dataclass(frozen=True)
class FileReadCase:
    case_id: str
    path: str


@dataclass(frozen=True)
class FileReadCaseResult:
    case_id: str
    path: str
    response: FileReadResponse


def validate_cases(
    cases: Sequence[FileReadCase],
)->tuple[FileReadCase, ...]:
    if isinstance(cases, (str, bytes)) or not isinstance(cases, Sequence):
        raise TypeError("cases must be a sequence of FileReadCase objects.")

    # avoid execution influence from changing original list
    snapshot = tuple(cases)

    if not snapshot:
        raise ValueError("The batch must contain at least one case.")

    seen_ids: set[str] = set()

    for index, case in enumerate(snapshot):
        prefix = f"Case {index + 1}"

        if not isinstance(case, FileReadCase):
            raise TypeError(f"{prefix}: expected a FileReadCase.")

        if not isinstance(case.case_id, str) or not case.case_id.strip():
            raise ValueError(f"{prefix}: case_id must be a non-empty string.")

        if case.case_id in seen_ids:
            raise ValueError(f"{prefix}: duplicate case_id.")

        if not isinstance(case.path, str):
            raise TypeError(f"{prefix}: path must be a string.")

        seen_ids.add(case.case_id)

    return snapshot
