from dataclasses import dataclass
from .expectations import FileReadExpectation
from collections.abc import Sequence
from .batch import FileReadCase, validate_cases


@dataclass(frozen=True)
class FileReadTestCase:
    case: FileReadCase
    expectation: FileReadExpectation


def validate_test_cases(
    cases: Sequence[FileReadTestCase],
) -> tuple[FileReadTestCase, ...]:
    if isinstance(cases, (str, bytes)) or not isinstance(cases, Sequence):
        raise TypeError(
            "cases must be a sequence of FileReadTestCase objects."
        )

    snapshot = tuple(cases)

    for index, item in enumerate(snapshot, start=1):
        if not isinstance(item, FileReadTestCase):
            raise TypeError(
                f"Case {index}: expected a FileReadTestCase."
            )

        if not isinstance(item.expectation, FileReadExpectation):
            raise TypeError(
                f"Case {index}: expected a FileReadExpectation."
            )

    validate_cases(tuple(item.case for item in snapshot))

    return snapshot
