"""Text feedback and evidence retention without model or MCP network calls."""
import asyncio
import base64
from hashlib import sha256
import unittest
from unittest.mock import AsyncMock, patch

from agents.base import AgentAdapter
from agents.models import AgentFinalAnswer, ReadFileCall, ReadFileFeedback
from attack_runner.agent_execution import AgentFileReadRecord, MCPReadExecutor, build_read_feedback
from attack_runner.agent_loop import AgentLoopConfig, run_agent_loop
from attack_runner.mcp_models import FileReadResponse


def response(content=b"", *, truncated=False, request_id="r1"):
    return FileReadResponse(
        request_id=request_id, policy_decision="allowed", execution_status="succeeded",
        reason="read", content_base64=base64.b64encode(content).decode("ascii"),
        returned_bytes=len(content), truncated=truncated, content_sha256=sha256(content).hexdigest(),
    )


class FeedbackTests(unittest.TestCase):
    def test_empty_unicode_and_truncated_text(self):
        for content, truncated in ((b"", False), ("你好".encode(), False), (b"abc", True)):
            with self.subTest(content=content):
                item = build_read_feedback(ReadFileCall("c1", "a"), response(content, truncated=truncated))
                self.assertTrue(item.succeeded)
                self.assertEqual(item.text, content.decode())
                self.assertEqual(item.truncated, truncated)
                self.assertEqual(item.call_id, "c1")

    def test_blocked_and_failed_reads(self):
        for policy, status in (("blocked", "not_started"), ("allowed", "failed"),
                               ("error", "not_started"), ("not_evaluated", "not_started")):
            raw = FileReadResponse(
                request_id="r1", policy_decision=policy, execution_status=status, reason="synthetic",
                content_base64=None, returned_bytes=0, truncated=None, content_sha256=None,
            )
            item = build_read_feedback(ReadFileCall("c1", "a"), raw)
            self.assertFalse(item.succeeded)
            self.assertEqual(item.reason, "synthetic")
            self.assertIsNone(item.text)
            self.assertIsNone(item.truncated)

    def test_invalid_utf8_and_split_character_preserve_read_success(self):
        for content, truncated in ((b"\xff", False), ("你".encode()[:2], True)):
            raw = response(content, truncated=truncated)
            item = build_read_feedback(ReadFileCall("c1", "a"), raw)
            self.assertEqual(item.reason, "text_decode_failed")
            self.assertFalse(item.succeeded)
            self.assertIsNone(item.text)
            self.assertEqual(raw.execution_status, "succeeded")
            self.assertEqual(raw.returned_bytes, len(content))

    def test_record_rejects_mismatched_call_id(self):
        with self.assertRaises(ValueError):
            AgentFileReadRecord(ReadFileCall("c1", "a"), response(),
                                ReadFileFeedback("other", True, "read", "", False))

    def test_executor_limit_validation(self):
        for limit in (True, 0, -1, 1.5):
            with self.subTest(limit=limit), self.assertRaises((TypeError, ValueError)):
                MCPReadExecutor(object(), max_read_bytes=limit)


class ExecutorTests(unittest.IsolatedAsyncioTestCase):
    async def test_mapping_and_snapshot_survive_later_calls(self):
        session = object()
        executor = MCPReadExecutor(session, max_read_bytes=32)
        raw = response(b"hello")
        with patch("attack_runner.agent_execution.read_file", AsyncMock(return_value=raw)) as read:
            call = ReadFileCall("c1", "public/a")
            feedback = await executor(call)
            read.assert_awaited_once_with(session, "public/a", max_read_bytes=32)
            snapshot = executor.records
            self.assertIs(snapshot[0].response, raw)
            self.assertIs(snapshot[0].feedback, feedback)
            self.assertEqual((snapshot[0].call.call_id, snapshot[0].response.request_id), ("c1", "r1"))
            await executor(ReadFileCall("c2", "public/b"))
            self.assertEqual(len(snapshot), 1)
            self.assertEqual(len(executor.records), 2)

    async def test_decode_failure_is_recorded(self):
        executor = MCPReadExecutor(object(), max_read_bytes=32)
        raw = response(b"\xff")
        with patch("attack_runner.agent_execution.read_file", AsyncMock(return_value=raw)):
            feedback = await executor(ReadFileCall("c1", "a"))
        self.assertFalse(feedback.succeeded)
        self.assertIs(executor.records[0].response, raw)

    async def test_error_and_cancellation_do_not_fabricate_records(self):
        for error in (RuntimeError("MCP error"), asyncio.CancelledError()):
            executor = MCPReadExecutor(object(), max_read_bytes=32)
            with patch("attack_runner.agent_execution.read_file", AsyncMock(side_effect=error)):
                with self.assertRaises(type(error)):
                    await executor(ReadFileCall("c1", "a"))
            self.assertEqual(executor.records, ())

    async def test_invalid_call_does_not_contact_mcp(self):
        executor = MCPReadExecutor(object(), max_read_bytes=32)
        with patch("attack_runner.agent_execution.read_file", AsyncMock()) as read:
            with self.assertRaises(TypeError):
                await executor("a")
            read.assert_not_awaited()

    async def test_loop_receives_feedback_and_executor_retains_evidence(self):
        class Agent(AgentAdapter):
            async def next_action(self, *, task, history):
                if not history:
                    return ReadFileCall("c1", "public/a")
                return AgentFinalAnswer(history[-1].text)
        executor = MCPReadExecutor(object(), max_read_bytes=32)
        with patch("attack_runner.agent_execution.read_file", AsyncMock(return_value=response(b"hello"))):
            result = await run_agent_loop(Agent(), "read", executor, AgentLoopConfig())
        self.assertEqual(result.final_answer.text, "hello")
        self.assertEqual(result.steps, 2)
        self.assertEqual(result.history, (executor.records[0].call, executor.records[0].feedback))
