"""Exercise the Runner client against the real stdio server with synthetic files.

Run in Linux: uv run --locked python -m unittest discover -s tests/integration -v
macOS skips these tests. Linux initialization failures must fail the tests.
"""

import asyncio
import base64
import json
from contextlib import asynccontextmanager
from hashlib import sha256
from pathlib import Path
import sys
import tempfile
import unittest
from uuid import UUID

from attack_runner.mcp_client import connect_filesystem_server, read_file
from attack_runner.batch import FileReadCase, run_file_batch
from attack_runner.mcp_models import FileReadResponse
from mcp_servers.filesystem_server.models import FileServiceConfig


@unittest.skipUnless(sys.platform == "linux", "Requires the Linux file platform")
class MCPStdioTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agentcrucible-mcp-")
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name) / "workspace"
        (self.workspace / "public").mkdir(parents=True)
        (self.workspace / "secret").mkdir()
        (self.workspace / "public/sample").write_bytes(b"\x00\xffabcdef")
        (self.workspace / "public/empty").write_bytes(b"")
        (self.workspace / "secret/token").write_text("SYNTHETIC-ONLY")
        (self.workspace.parent / "outside").write_text("SYNTHETIC-OUTSIDE")
        self.request_ids = set()
        self.max_read_bytes = 4
        self.audit_path = self.workspace.parent / "events.jsonl"

    @asynccontextmanager
    async def connect(self, *, allow_public=True):
        config = FileServiceConfig(
            workspace_root=str(self.workspace),
            authorized_roots=("public",) if allow_public else (),
            max_read_bytes=self.max_read_bytes,
        )
        # Keep protocol contexts in the same task; SDK owns subprocess cleanup.
        async with asyncio.timeout(30):
            async with connect_filesystem_server(config, audit_path=self.audit_path) as session:
                yield session

    async def read_file(self, session, path):
        response = await read_file(
            session, path, max_read_bytes=self.max_read_bytes,
        )
        self.assertIsInstance(response, FileReadResponse)
        data = response.model_dump()
        self.assertIsInstance(data, dict)
        self.assertEqual(set(data), {
            "request_id", "policy_decision", "execution_status", "reason",
            "content_base64", "returned_bytes", "truncated", "content_sha256",
        })
        self.assertEqual(UUID(data["request_id"]).version, 4)
        self.assertNotIn(data["request_id"], self.request_ids)
        self.request_ids.add(data["request_id"])
        return data

    def assert_failure(self, data, policy, reason):
        self.assertEqual(data["policy_decision"], policy)
        self.assertEqual(data["execution_status"], "not_started")
        self.assertEqual(data["reason"], reason)
        self.assertIsNone(data["content_base64"])
        self.assertIsNone(data["content_sha256"])
        self.assertIsNone(data["truncated"])
        self.assertEqual(data["returned_bytes"], 0)

    async def test_discovery_and_binary_reads(self):
        async with self.connect() as session:
            tools = (await session.list_tools()).tools
            self.assertEqual([tool.name for tool in tools], ["read_file"])
            schema = tools[0].input_schema
            self.assertEqual(set(schema["properties"]), {"path"})
            self.assertEqual(schema["required"], ["path"])
            self.assertEqual(schema["properties"]["path"]["type"], "string")
            for path, content, truncated in (
                ("public/sample", b"\x00\xffab", True),
                ("public/empty", b"", False),
            ):
                with self.subTest(path=path):
                    data = await self.read_file(session, path)
                    self.assertEqual(data["policy_decision"], "allowed")
                    self.assertEqual(data["execution_status"], "succeeded")
                    self.assertEqual(base64.b64decode(data["content_base64"], validate=True), content)
                    self.assertEqual(data["content_sha256"], sha256(content).hexdigest())
                    self.assertEqual(data["returned_bytes"], len(content))
                    self.assertIs(data["truncated"], truncated)

    async def test_rejections_and_recovery_on_same_session(self):
        async with self.connect() as session:
            cases = (
                ("secret/token", "blocked", "outside_authorized_roots"),
                ("public/../secret/token", "blocked", "outside_authorized_roots"),
                ("../outside", "blocked", "outside_workspace"),
                (str(self.workspace.parent / "outside"), "blocked", "outside_workspace"),
                ("public/missing", "not_evaluated", "file_not_found"),
            )
            for path, policy, reason in cases:
                with self.subTest(path=path):
                    self.assert_failure(await self.read_file(session, path), policy, reason)
            data = await self.read_file(session, "public/sample")
            self.assertEqual(data["execution_status"], "succeeded")
            self.assertEqual(base64.b64decode(data["content_base64"]), b"\x00\xffab")

    async def test_default_empty_allowlist(self):
        async with self.connect(allow_public=False) as session:
            data = await self.read_file(session, "public/sample")
            self.assert_failure(data, "blocked", "no_authorized_roots")

    async def test_runner_batch_success_rejection_and_recovery(self):
        config = FileServiceConfig(str(self.workspace), ("public",), self.max_read_bytes)
        cases = (
            FileReadCase("first", "public/sample"),
            FileReadCase("denied", "secret/token"),
            FileReadCase("last", "public/empty"),
        )
        async with asyncio.timeout(30):
            results = await run_file_batch(cases, config, audit_path=self.audit_path)
        self.assertEqual([r.case_id for r in results], [c.case_id for c in cases])
        self.assertEqual([r.path for r in results], [c.path for c in cases])
        self.assertTrue(all(isinstance(r.response, FileReadResponse) for r in results))
        self.assertEqual(len({r.response.request_id for r in results}), 3)
        first, denied, last = (r.response for r in results)
        self.assertEqual(first.execution_status, "succeeded")
        self.assertEqual(first.policy_decision, "allowed")
        self.assertEqual(base64.b64decode(first.content_base64), b"\x00\xffab")
        self.assertTrue(first.truncated)
        self.assert_failure(denied.model_dump(), "blocked", "outside_authorized_roots")
        self.assertEqual(last.execution_status, "succeeded")
        self.assertEqual(last.content_base64, "")
        self.assertFalse(last.truncated)
        records = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        self.assertEqual(len(records), len(results))
        for record, result in zip(records, results, strict=True):
            self.assertEqual(record["request_id"], result.response.request_id)
            self.assertEqual(record["original_path"], result.path)
            self.assertEqual(record["policy_decision"], result.response.policy_decision)
            self.assertEqual(record["execution_status"], result.response.execution_status)
            self.assertEqual(record["authorized_roots"], [str(self.workspace / "public")])
            self.assertEqual(record["resolved_path"], str(self.workspace / result.path))
            self.assertNotIn("content", record)
            self.assertNotIn("content_base64", record)


if __name__ == "__main__":
    unittest.main()
