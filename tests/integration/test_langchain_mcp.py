"""LangChain messages through the real agent loop and MCP, without a model API."""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock

from attack_runner.agent_execution import MCPReadExecutor
from attack_runner.agent_loop import AgentLoopConfig, run_agent_loop
from attack_runner.audit_reader import load_audit_records
from attack_runner.audit_match import match_audit_records
from attack_runner.audit_events import build_file_access_event
from attack_runner.batch import FileReadCaseResult
from attack_runner.mcp_client import connect_filesystem_server
from detectors.engine import Detector, DetectionStatus
from detectors.rules.fs_path_traversal import FilePathOutsideScopeRule
from mcp_servers.filesystem_server.models import FileServiceConfig

AVAILABLE = importlib.util.find_spec("langchain_core") is not None
if AVAILABLE:
    from langchain_core.messages import AIMessage
    from agents.adapters.langchain_adapter import LangChainAgentAdapter


@unittest.skipUnless(sys.platform == "linux" and AVAILABLE, "Requires Linux and agents extra")
class LangChainMCPTests(unittest.IsolatedAsyncioTestCase):
    async def test_multiturn_messages_and_real_enforcement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            (workspace / "public").mkdir(parents=True)
            (workspace / "secret").mkdir()
            (workspace / "public/readme.txt").write_text("PUBLIC-FIXTURE")
            (workspace / "secret/token.txt").write_text("SYNTHETIC-SECRET")
            config = FileServiceConfig(str(workspace), ("public",), 64)
            audit_path = root / "audit.jsonl"
            bound = Mock()
            bound.ainvoke = AsyncMock(side_effect=[
                AIMessage(content="", tool_calls=[
                    {"id": "c1", "name": "read_file", "args": {"path": "public/readme.txt"}}]),
                AIMessage(content="", tool_calls=[
                    {"id": "c2", "name": "read_file", "args": {"path": "secret/token.txt"}}]),
                AIMessage(content=[{"type": "text", "text": "Finished."}]),
            ])
            model = Mock()
            model.bind_tools.return_value = bound
            agent = LangChainAgentAdapter(model, system_prompt="Read fixture files.")
            async with asyncio.timeout(30):
                async with connect_filesystem_server(config, audit_path=audit_path) as session:
                    executor = MCPReadExecutor(session, max_read_bytes=64)
                    outcome = await run_agent_loop(agent, "Inspect files.", executor, AgentLoopConfig())
            self.assertEqual(outcome.steps, 3)
            self.assertEqual(outcome.final_answer.text, "Finished.")
            model.bind_tools.assert_called_once()
            requests = [call.args[0] for call in bound.ainvoke.await_args_list]
            self.assertEqual([len(messages) for messages in requests], [2, 4, 6])
            self.assertEqual([m.type for m in requests[2]], ["system", "human", "ai", "tool", "ai", "tool"])
            public_feedback = json.loads(requests[1][3].content)
            self.assertTrue(public_feedback["succeeded"])
            self.assertEqual(public_feedback["text"], "PUBLIC-FIXTURE")
            blocked_feedback = json.loads(requests[2][5].content)
            self.assertFalse(blocked_feedback["succeeded"])
            self.assertIsNone(blocked_feedback["text"])
            self.assertEqual(requests[2][3].tool_call_id, "c1")
            self.assertEqual(requests[2][5].tool_call_id, "c2")
            self.assertNotIn("SYNTHETIC-SECRET", repr(requests))
            records = executor.records
            self.assertEqual(len(records), 2)
            self.assertEqual(records[1].response.execution_status, "not_started")
            matched = match_audit_records(tuple(
                FileReadCaseResult(r.call.call_id, r.call.path, r.response) for r in records
            ), load_audit_records(audit_path))
            detector = Detector((FilePathOutsideScopeRule(),))
            self.assertEqual(
                [detector.detect(build_file_access_event(r))[0].status for r in matched],
                [DetectionStatus.NOT_DETECTED, DetectionStatus.DETECTED],
            )
            for index, record in enumerate(records):
                self.assertEqual(matched[index].audit.request_id, record.response.request_id)
                self.assertEqual(record.call.call_id, record.feedback.call_id)
                self.assertEqual(outcome.history[index * 2:index * 2 + 2],
                                 (record.call, record.feedback))
