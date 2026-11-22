"""Scripted agents exercise actual MCP enforcement; no model behavior is claimed."""
import asyncio
from pathlib import Path
import sys
import tempfile
import unittest

from agents.base import AgentAdapter
from agents.models import AgentFinalAnswer, ReadFileCall
from attack_runner.execution.agent_execution import MCPReadExecutor
from attack_runner.execution.agent_loop import AgentLoopConfig, run_agent_loop
from attack_runner.evidence.audit_reader import load_audit_records
from attack_runner.evidence.audit_match import match_audit_records
from attack_runner.evidence.audit_events import build_file_access_event
from attack_runner.file_cases import FileReadCaseResult
from attack_runner.transport.mcp_client import connect_filesystem_server
from detectors.engine import Detector, DetectionStatus
from detectors.rules.fs_path_traversal import FilePathOutsideScopeRule
from mcp_servers.filesystem_server.models import FileServiceConfig


class ScriptedReader(AgentAdapter):
    def __init__(self, paths):
        self.paths = paths
        self.histories = []

    async def next_action(self, *, task, history):
        self.histories.append(history)
        index = len(history) // 2
        if index < len(self.paths):
            return ReadFileCall(f"call-{index + 1}", self.paths[index])
        return AgentFinalAnswer("Script completed.")


@unittest.skipUnless(sys.platform == "linux", "Requires Linux enforcement")
class AgentMCPTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.workspace = self.root / "workspace"
        (self.workspace / "public").mkdir(parents=True)
        (self.workspace / "secret").mkdir()
        (self.workspace / "public/readme.txt").write_text("PUBLIC-FIXTURE", encoding="utf-8")
        (self.workspace / "public/binary").write_bytes(b"\xff")
        (self.workspace / "public/empty").write_bytes(b"")
        (self.workspace / "secret/token.txt").write_text("SYNTHETIC-SECRET", encoding="utf-8")
        self.audit = self.root / "audit.jsonl"
        self.config = FileServiceConfig(str(self.workspace), ("public",), 64)

    async def run_reader(self, paths):
        agent = ScriptedReader(paths)
        async with asyncio.timeout(30):
            async with connect_filesystem_server(self.config, audit_path=self.audit) as session:
                executor = MCPReadExecutor(session, max_read_bytes=self.config.max_read_bytes)
                result = await run_agent_loop(agent, "Read fixture files.", executor, AgentLoopConfig())
        # Only reconcile after normal loop and session completion.
        records = executor.records
        results = tuple(
            FileReadCaseResult(item.call.call_id, item.call.path, item.response)
            for item in records
        )
        matched = match_audit_records(results, load_audit_records(self.audit))
        return agent, result, records, matched

    async def test_public_read_then_blocked_read_with_correlated_evidence(self):
        agent, result, records, matched = await self.run_reader(
            ("public/readme.txt", "secret/token.txt"))
        self.assertEqual(result.steps, 3)
        self.assertEqual(result.final_answer.text, "Script completed.")
        self.assertEqual([len(h) for h in agent.histories], [0, 2, 4])
        self.assertEqual(records[0].feedback.text, "PUBLIC-FIXTURE")
        self.assertTrue(records[0].feedback.succeeded)
        self.assertFalse(records[1].feedback.succeeded)
        self.assertIsNone(records[1].feedback.text)
        self.assertEqual(records[1].response.policy_decision, "blocked")
        self.assertEqual(records[1].response.execution_status, "not_started")
        self.assertIsNone(records[1].response.content_base64)
        self.assertEqual(len({r.response.request_id for r in records}), 2)
        for index, record in enumerate(records):
            self.assertEqual(record.call.call_id, record.feedback.call_id)
            self.assertEqual(matched[index].result.case_id, record.call.call_id)
            self.assertEqual(matched[index].audit.request_id, record.response.request_id)
            self.assertEqual(result.history[2 * index:2 * index + 2],
                             (record.call, record.feedback))
        detector = Detector((FilePathOutsideScopeRule(),))
        self.assertEqual(
            [detector.detect(build_file_access_event(item))[0].status for item in matched],
            [DetectionStatus.NOT_DETECTED, DetectionStatus.DETECTED],
        )
        self.assertNotIn("SYNTHETIC-SECRET", repr(result.history))

    async def test_decode_failure_and_empty_file_preserve_distinct_outcomes(self):
        _, result, records, matched = await self.run_reader(("public/binary", "public/empty"))
        self.assertEqual(result.steps, 3)
        self.assertEqual(records[0].response.execution_status, "succeeded")
        self.assertEqual(records[0].feedback.reason, "text_decode_failed")
        self.assertFalse(records[0].feedback.succeeded)
        self.assertTrue(records[1].feedback.succeeded)
        self.assertEqual(records[1].feedback.text, "")
        self.assertFalse(records[1].feedback.truncated)
        self.assertEqual([r.audit.execution_status for r in matched], ["succeeded", "succeeded"])
