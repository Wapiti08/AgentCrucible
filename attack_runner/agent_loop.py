"""
interface to catch up the read request from Agent

"""
from dataclasses import dataclass
import math
from collections.abc import Awaitable, Callable
from typing import Literal
from agents.models import AgentFinalAnswer, AgentHistoryItem
from agents.models import ReadFileCall, ReadFileFeedback
import asyncio

from agents.base import AgentAdapter

ReadFileExecutor = Callable[
    [ReadFileCall],
    Awaitable[ReadFileFeedback]
]


@dataclass(frozen=True)
class AgentLoopConfig:
    max_steps: int = 8
    step_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        # exclude True, False as well
        if type(self.max_steps) is not int:
            raise TypeError("max_steps must be an integer.")

        if self.max_steps <= 0:
            raise ValueError("max_steps must be positive.")

        timeout = self.step_timeout_seconds

        if type(timeout) not in (int, float):
            raise TypeError(
                "step_timeout_seconds must be a number."
            )

        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError(
                "step_timeout_seconds must be finite and positive."
            )


@dataclass(frozen=True)
class AgentLoopResult:
    final_answer: AgentFinalAnswer
    history: tuple[AgentHistoryItem, ...]
    steps: int


class AgentLoopAbortedError(RuntimeError):
    def __init__(
        self,
        *,
        reason: Literal[
            "step_limit",
            "timeout",
            "invalid_action",
            "duplicate_call_id",
            "invalid_feedback",
            "agent_error",
            "tool_error",
        ],
        phase: Literal["agent", "tool", "limit"],
        history: tuple[AgentHistoryItem, ...],
        steps: int,
        pending_call: ReadFileCall | None = None,
    ) -> None:
        super().__init__(
            f"Agent loop aborted during {phase}: {reason}."
        )
        self.reason = reason
        self.phase = phase
        self.history = history
        self.steps = steps
        self.pending_call = pending_call


async def run_agent_loop(
    # potential next call
    agent: AgentAdapter,
    task: str,
    execute_read: ReadFileExecutor,
    config: AgentLoopConfig,
) -> AgentLoopResult:
    if not isinstance(agent, AgentAdapter):
        raise TypeError("agent must implement AgentAdapter.")

    if not isinstance(task, str):
        raise TypeError("task must be a string.")

    if not callable(execute_read):
        raise TypeError("execute_read must be callable.")

    if not isinstance(config, AgentLoopConfig):
        raise TypeError("config must be an AgentLoopConfig.")

    history: list[AgentHistoryItem] = []
    seen_call_ids: set[str] = set()

    for step in range(1, config.max_steps + 1):
        phase: Literal["agent", "tool", "limit"] = "agent"
        pending_call: ReadFileCall | None = None
        timeout = asyncio.timeout(config.step_timeout_seconds)

        try:
            async with timeout:
                # next call action
                action = await agent.next_action(
                    task=task,
                    history=tuple(history),
                )

                # check whether it is final answer, return directly if it is
                if isinstance(action, AgentFinalAnswer):
                    return AgentLoopResult(
                        final_answer=action,
                        history=tuple(history),
                        steps = step,
                    )

                # check whether not read call
                if not isinstance(action, ReadFileCall):
                    raise AgentLoopAbortedError(
                        reason="invalid_action",
                        phase=phase,
                        history=tuple(history),
                        steps=step,
                    )

                # check whether it is repeated call - ReadFileCall
                if action.call_id in seen_call_ids:
                    raise AgentLoopAbortedError(
                        reason="duplicate_call_id",
                        phase=phase,
                        history=tuple(history),
                        steps=step,
                    )

                seen_call_ids.add(action.call_id)
                pending_call = action
                phase = "tool"

                feedback = await execute_read(action)

                if (
                    not isinstance(feedback, ReadFileFeedback)
                    or feedback.call_id != action.call_id
                ):
                    raise AgentLoopAbortedError(
                        reason="invalid_feedback",
                        phase=phase,
                        history=tuple(history),
                        steps=step,
                        pending_call=pending_call,
                    )
                # compose a tuple for action and its matched feedback
                history.extend((action, feedback))
                pending_call = None

        except AgentLoopAbortedError:
            raise

        except Exception as exc:
            if timeout.expired():
                reason = "timeout"
            elif phase == "agent":
                reason = "agent_error"
            else:
                reason = "tool_error"

            raise AgentLoopAbortedError(
                reason=reason,
                phase=phase,
                history=tuple(history),
                steps=step,
                pending_call=pending_call,
            ) from exc

    raise AgentLoopAbortedError(
        reason="step_limit",
        phase="limit",
        history=tuple(history),
        steps=config.max_steps,
    )
