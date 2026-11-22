"""
execution orchestration
"""

from dataclasses import dataclass
from typing import Literal

from pathlib import Path

from agents.base import AgentAdapter
from mcp_servers.filesystem_server.models import FileServiceConfig
from attack_runner.transport.mcp_client import connect_filesystem_server

from .agent_execution import AgentFileReadRecord, MCPReadExecutor
from .agent_loop import (
    AgentLoopAbortedError,
    AgentLoopConfig,
    AgentLoopResult,
    run_agent_loop,
)

# define normal behaviour
@dataclass(frozen=True)
class AgentRunResult:
    loop_result: AgentLoopResult
    records: tuple[AgentFileReadRecord, ...]


# define error process
class AgentRunAbortedError(RuntimeError):
    def __init__(
        self,
        *,
        phase: Literal["connect", "loop", "close"],
        records: tuple[AgentFileReadRecord, ...],
        loop_result: AgentLoopResult | None = None,
        loop_error: AgentLoopAbortedError | None = None,
    ) -> None:
        super().__init__(
            f"Agent run aborted during {phase}."
        )

        self.phase = phase
        self.records = records
        self.loop_result = loop_result
        self.loop_error = loop_error


async def execute_agent_run(
    agent: AgentAdapter,
    *,
    task: str,
    filesystem: FileServiceConfig,
    loop: AgentLoopConfig,
    audit_path: Path,
) -> AgentRunResult:
    phase: Literal["connect", "loop", "close"] = "connect"
    executor: MCPReadExecutor | None = None
    loop_result: AgentLoopResult | None = None
    loop_error: AgentLoopAbortedError | None = None

    try:
        async with connect_filesystem_server(
            filesystem,
            audit_path=audit_path,
        ) as session:
            phase = "loop"
            executor = MCPReadExecutor(
                session,
                max_read_bytes=filesystem.max_read_bytes,
            )

            try:
                loop_result = await run_agent_loop(
                    agent=agent,
                    task=task,
                    execute_read=executor,
                    config=loop,
                )
            except AgentLoopAbortedError as exc:
                loop_error = exc

            phase = "close"

    except Exception as exc:
        raise AgentRunAbortedError(
            phase=phase,
            records=executor.records if executor is not None else (),
            loop_result=loop_result,
            loop_error=loop_error,
        ) from exc

    records = executor.records if executor is not None else ()

    if loop_error is not None:
        raise AgentRunAbortedError(
            phase="loop",
            records=records,
            loop_error=loop_error,
        ) from loop_error

    if loop_result is None:
        raise RuntimeError("Agent run ended without a loop result.")

    return AgentRunResult(
        loop_result=loop_result,
        records=records,
    )
