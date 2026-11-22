"""Exercise orchestration with the real loop/executor and fake MCP transport."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from agents.base import AgentAdapter
from agents.models import AgentFinalAnswer, ReadFileCall
from attack_runner.execution.agent_loop import AgentLoopConfig
from attack_runner.execution.agent_run import AgentRunAbortedError, execute_agent_run
from attack_runner.transport.mcp_models import FileReadResponse
from mcp_servers.filesystem_server.models import FileServiceConfig


class ScriptedAgent(AgentAdapter):
    def __init__(self, actions):
        self.actions = iter(actions)

    async def next_action(self, *, task, history):
        action = next(self.actions)
        if isinstance(action, BaseException):
            raise action
        return action


class AgentRunTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.closed = False
        self.connect_error = None
        self.close_error = None
        self.response = FileReadResponse(
            request_id="r1", policy_decision="blocked", execution_status="not_started",
            reason="outside_scope", content_base64=None, returned_bytes=0,
            truncated=None, content_sha256=None,
        )

        @asynccontextmanager
        async def connect(config, *, audit_path):
            if self.connect_error:
                raise self.connect_error
            try:
                yield object()
            finally:
                self.closed = True
                if self.close_error:
                    raise self.close_error

        self.enterContext(patch("attack_runner.execution.agent_run.connect_filesystem_server", connect))
        self.read = self.enterContext(patch(
            "attack_runner.execution.agent_execution.read_file",
            AsyncMock(return_value=self.response),
        ))

    async def run_script(self, actions, *, max_steps=3):
        return await execute_agent_run(
            ScriptedAgent(actions), task="test task",
            filesystem=FileServiceConfig("/test", ("public",), 1024),
            loop=AgentLoopConfig(max_steps=max_steps),
            audit_path=Path("/audit/events.jsonl"),
        )

    async def test_success_returns_answer_and_records_after_cleanup(self):
        result = await self.run_script([ReadFileCall("c1", "secret"), AgentFinalAnswer("done")])
        self.assertTrue(self.closed)
        self.assertEqual(result.loop_result.steps, 2)
        self.assertEqual(result.loop_result.final_answer.text, "done")
        self.assertEqual(len(result.records), 1)
        self.assertIs(result.records[0].response, self.response)
        self.assertEqual(result.loop_result.history[1], result.records[0].feedback)

    async def test_connect_failure_has_no_execution_evidence(self):
        self.connect_error = OSError("connect failed")
        with self.assertRaises(AgentRunAbortedError) as caught:
            await self.run_script([])
        error = caught.exception
        self.assertEqual(error.phase, "connect")
        self.assertEqual(error.records, ())
        self.assertIs(error.__cause__, self.connect_error)
        self.read.assert_not_awaited()

    async def test_step_limit_preserves_completed_read(self):
        with self.assertRaises(AgentRunAbortedError) as caught:
            await self.run_script([ReadFileCall("c1", "secret")], max_steps=1)
        error = caught.exception
        self.assertTrue(self.closed)
        self.assertEqual(error.phase, "loop")
        self.assertEqual(error.loop_error.reason, "step_limit")
        self.assertEqual(len(error.records), 1)
        self.assertEqual(len(error.loop_error.history), 2)
        self.assertIs(error.__cause__, error.loop_error)

    async def test_close_failure_preserves_successful_answer(self):
        self.close_error = OSError("close failed")
        with self.assertRaises(AgentRunAbortedError) as caught:
            await self.run_script([ReadFileCall("c1", "secret"), AgentFinalAnswer("done")])
        error = caught.exception
        self.assertEqual(error.phase, "close")
        self.assertEqual(error.loop_result.final_answer.text, "done")
        self.assertEqual(len(error.records), 1)
        self.assertIsNone(error.loop_error)
        self.assertIs(error.__cause__, self.close_error)

    async def test_loop_and_close_failure_preserve_both_errors(self):
        self.close_error = OSError("close failed")
        with self.assertRaises(AgentRunAbortedError) as caught:
            await self.run_script([ReadFileCall("c1", "secret")], max_steps=1)
        error = caught.exception
        self.assertEqual(error.phase, "close")
        self.assertEqual(error.loop_error.reason, "step_limit")
        self.assertEqual(len(error.records), 1)
        self.assertIs(error.__cause__, self.close_error)

    async def test_tool_failure_keeps_pending_call_without_fabricated_record(self):
        self.read.side_effect = OSError("tool failed")
        call = ReadFileCall("c1", "secret")
        with self.assertRaises(AgentRunAbortedError) as caught:
            await self.run_script([call])
        error = caught.exception
        self.assertTrue(self.closed)
        self.assertEqual(error.phase, "loop")
        self.assertEqual(error.loop_error.reason, "tool_error")
        self.assertEqual(error.loop_error.pending_call, call)
        self.assertEqual(error.records, ())

    async def test_cancellation_propagates_and_closes_session(self):
        with self.assertRaises(asyncio.CancelledError):
            await self.run_script([asyncio.CancelledError()])
        self.assertTrue(self.closed)
        self.read.assert_not_awaited()
