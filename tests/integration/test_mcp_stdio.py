"""Exercise the real stdio server in a Linux subprocess using synthetic files.

Run in Linux: uv run --locked python -m unittest discover -s tests/integration -v
macOS skips these tests. Linux initialization failures must fail the tests.
"""

import asyncio
import base64
from contextlib import asynccontextmanager
from hashlib import sha256
from pathlib import Path
import sys
import tempfile
import unittest
from uuid import UUID

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


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

    @asynccontextmanager
    async def connect(self, *, allow_public=True):
        args = ["-B", "-m", "mcp_servers.filesystem_server.server",
                "--workspace", str(self.workspace), "--max-read-bytes", "4"]
        if allow_public:
            args.extend(["--allowed-root", "public"])
        parameters = StdioServerParameters(
            command=sys.executable,
            args=args,
            cwd=Path(__file__).resolve().parents[2],
        )
        # Keep protocol contexts in the same task; SDK owns subprocess cleanup.
        async with asyncio.timeout(30):
            async with stdio_client(parameters) as (read, write):
                async with ClientSession(read, write, read_timeout_seconds=10) as session:
                    await session.initialize()
                    yield session

    async def read_file(self, session, path):
        response = await session.call_tool("read_file", {"path": path})
        data = response.structured_content
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


if __name__ == "__main__":
    unittest.main()
