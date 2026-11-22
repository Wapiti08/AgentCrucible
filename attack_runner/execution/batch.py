from attack_runner.file_cases import FileReadCase, FileReadCaseResult, validate_cases
from pathlib import Path
from collections.abc import Sequence
from typing import Literal
from mcp_servers.filesystem_server.models import FileServiceConfig
from attack_runner.transport.mcp_client import connect_filesystem_server, read_file

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