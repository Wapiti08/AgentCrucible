"""Runner-controlled agent loop contracts with deterministic adapters."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from agents.base import AgentAdapter
from agents.models import AgentFinalAnswer, ReadFileCall, ReadFileFeedback
from attack_runner.execution.agent_loop import AgentLoopConfig, AgentLoopAbortedError, run_agent_loop


class ScriptedAgent(AgentAdapter):
    def __init__(self, actions):
        self.actions = iter(actions)
        self.inputs = []

    async def next_action(self, *, task, history):
        self.inputs.append((task, history))
        action = next(self.actions)
        if isinstance(action, Exception):
            raise action
        return action


def feedback(call_id="c1"):
    return ReadFileFeedback(call_id, True, "read", "", False)


class ConfigTests(unittest.TestCase):
    def test_invalid_limits(self):
        for kwargs in (
            {"max_steps": True}, {"max_steps": 0}, {"max_steps": 1.5},
            {"step_timeout_seconds": False}, {"step_timeout_seconds": 0},
            {"step_timeout_seconds": float("nan")},
            {"step_timeout_seconds": float("inf")},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises((TypeError, ValueError)):
                AgentLoopConfig(**kwargs)


class AgentLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_final_answer_without_tool(self):
        execute = AsyncMock()
        answer = AgentFinalAnswer("")
        result = await run_agent_loop(ScriptedAgent([answer]), "task", execute, AgentLoopConfig())
        self.assertIs(result.final_answer, answer)
        self.assertEqual((result.steps, result.history), (1, ()))
        execute.assert_not_awaited()

    async def test_multiple_calls_and_failed_feedback_continue(self):
        first, second = ReadFileCall("c1", "public/a"), ReadFileCall("c2", "../secret")
        good = feedback()
        blocked = ReadFileFeedback("c2", False, "blocked", None, None)
        agent = ScriptedAgent([first, second, AgentFinalAnswer("done")])
        result = await run_agent_loop(agent, "task", AsyncMock(side_effect=[good, blocked]), AgentLoopConfig())
        self.assertEqual(result.history, (first, good, second, blocked))
        self.assertEqual(result.steps, 3)
        self.assertEqual(agent.inputs, [
            ("task", ()), ("task", (first, good)), ("task", result.history),
        ])

    async def test_duplicate_id_does_not_execute_twice(self):
        call = ReadFileCall("c1", "a")
        execute = AsyncMock(return_value=feedback())
        with self.assertRaises(AgentLoopAbortedError) as caught:
            await run_agent_loop(ScriptedAgent([call, call]), "task", execute, AgentLoopConfig())
        error = caught.exception
        self.assertEqual((error.reason, error.steps), ("duplicate_call_id", 2))
        self.assertEqual(len(error.history), 2)
        self.assertIsNone(error.pending_call)
        execute.assert_awaited_once()

    async def test_invalid_action(self):
        execute = AsyncMock()
        with self.assertRaises(AgentLoopAbortedError) as caught:
            await run_agent_loop(ScriptedAgent(["bad"]), "task", execute, AgentLoopConfig())
        self.assertEqual(caught.exception.reason, "invalid_action")
        execute.assert_not_awaited()

    async def test_invalid_feedback_preserves_pending_call(self):
        call = ReadFileCall("c1", "")
        for value in (None, feedback("other")):
            with self.subTest(value=value), self.assertRaises(AgentLoopAbortedError) as caught:
                await run_agent_loop(ScriptedAgent([call]), "task", AsyncMock(return_value=value), AgentLoopConfig())
            self.assertEqual(caught.exception.reason, "invalid_feedback")
            self.assertEqual(caught.exception.history, ())
            self.assertIs(caught.exception.pending_call, call)

    async def test_step_limit_retains_completed_pair(self):
        call = ReadFileCall("c1", "a")
        with self.assertRaises(AgentLoopAbortedError) as caught:
            await run_agent_loop(ScriptedAgent([call]), "task", AsyncMock(return_value=feedback()),
                                 AgentLoopConfig(max_steps=1))
        error = caught.exception
        self.assertEqual((error.reason, error.phase, error.steps), ("step_limit", "limit", 1))
        self.assertEqual(len(error.history), 2)
        self.assertIsNone(error.pending_call)

    async def test_agent_and_tool_errors_preserve_cause(self):
        for phase in ("agent", "tool"):
            cause = TimeoutError("upstream timeout, not the loop deadline")
            call = ReadFileCall("c1", "a")
            agent = ScriptedAgent([cause if phase == "agent" else call])
            execute = AsyncMock(side_effect=cause)
            with self.subTest(phase=phase), self.assertRaises(AgentLoopAbortedError) as caught:
                await run_agent_loop(agent, "task", execute, AgentLoopConfig())
            self.assertEqual(caught.exception.reason, phase + "_error")
            self.assertIs(caught.exception.__cause__, cause)
            self.assertEqual(caught.exception.pending_call, call if phase == "tool" else None)

    async def test_deadline_during_agent_and_tool(self):
        async def wait_forever(*args, **kwargs):
            await asyncio.Event().wait()
        for phase in ("agent", "tool"):
            call = ReadFileCall("c1", "a")
            agent = ScriptedAgent([call])
            execute = AsyncMock(side_effect=wait_forever)
            if phase == "agent":
                agent.next_action = AsyncMock(side_effect=wait_forever)
            with self.subTest(phase=phase), self.assertRaises(AgentLoopAbortedError) as caught:
                await run_agent_loop(agent, "task", execute, AgentLoopConfig(step_timeout_seconds=0.02))
            error = caught.exception
            self.assertEqual((error.reason, error.phase), ("timeout", phase))
            self.assertEqual(error.pending_call, call if phase == "tool" else None)

    async def test_one_timeout_context_covers_agent_and_tool(self):
        contexts = []
        real_timeout = asyncio.timeout
        def track(delay):
            context = real_timeout(delay)
            contexts.append(context)
            return context
        class CheckingAgent(AgentAdapter):
            async def next_action(self, **kwargs):
                self_context = contexts[-1]
                self.assertion = self_context.when()
                return ReadFileCall("c1", "a")
        agent = CheckingAgent()
        async def execute(call):
            self.assertEqual(len(contexts), 1)
            self.assertEqual(contexts[0].when(), agent.assertion)
            return feedback()
        with patch("attack_runner.execution.agent_loop.asyncio.timeout", side_effect=track):
            with self.assertRaises(AgentLoopAbortedError) as caught:
                await run_agent_loop(agent, "task", execute, AgentLoopConfig(max_steps=1))
        self.assertEqual(caught.exception.reason, "step_limit")

    async def test_external_cancellation_propagates(self):
        entered = asyncio.Event()
        async def execute(call):
            entered.set()
            await asyncio.Event().wait()
        task = asyncio.create_task(run_agent_loop(
            ScriptedAgent([ReadFileCall("c1", "a")]), "task", execute, AgentLoopConfig()))
        try:
            await asyncio.wait_for(entered.wait(), timeout=1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
