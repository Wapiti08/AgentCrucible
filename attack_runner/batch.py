from pathlib import Path
from dataclasses import dataclass
from collections.abc import Sequence
from .mcp_models import FileReadResponse
from typing import Literal
from mcp_servers.filesystem_server.models import FileServiceConfig
from .mcp_client import connect_filesystem_server, read_file

@dataclass(frozen=True)
class FileReadCase:
    case_id: str
    path: str


@dataclass(frozen=True)
class FileReadCaseResult:
    case_id: str
    path: str
    response: FileReadResponse


class BatchAbortedError(RuntimeError):
    """A batch stopped before it could finish normally."""

    def __init__(
        self,
        *,
        phase: Literal["connect", "call", "close"],
        failed_case: FileReadCase | None,
        completed_results: tuple[FileReadCaseResult, ...],
    ) -> None:
        """
        connect: initialize or handshake failed
        call: call or response check failed
        close: failed when existing the connection
        """
        super().__init__(f"File-read batch aborted during {phase}.")
        self.phase = phase
        self.failed_case = failed_case
        self.completed_results = completed_results


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


async def run_file_batch(
    cases: Sequence[FileReadCase],
    config: FileServiceConfig,
        *,
    audit_path: Path,
) -> tuple[FileReadCaseResult, ...]:
    """Run a batch of file-read cases against the MCP filesystem server."""
    # verify cases
    validated_cases = validate_cases(cases)

    completed: list[FileReadCaseResult] = []
    phase: Literal["connect", "call", "close"] = "connect"
    current_case: FileReadCase | None = None

    try:
        async with connect_filesystem_server(
                    config,
                    audit_path=audit_path,
                ) as session:
            for case in validated_cases:
                # successfully connected, now call the tool
                phase = "call"
                current_case = case

                response = await read_file(
                    session,
                    case.path,
                    max_read_bytes=config.max_read_bytes,
                )

                completed.append(
                    FileReadCaseResult(
                        case_id=case.case_id,
                        path=case.path,
                        response=response,
                    )
                )
                current_case = None
            phase = "close"

    except Exception as exc:
        raise BatchAbortedError(
            phase=phase,
            failed_case=current_case,
            completed_results=tuple(completed),
        ) from exc

    return tuple(completed)