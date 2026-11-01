"""Audit persistence and fail-closed tool behavior with synthetic records."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from mcp_servers.filesystem_server.audit import (
    AuditWriteError, JsonlAuditWriter, build_audit_record,
)
from mcp_servers.filesystem_server.models import ReadResult, PolicyDecision, ExecutionStatus
from mcp_servers.filesystem_server.tools import FileTools


class AuditTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="audit-test-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "events.jsonl"

    def result(self, request_id="r"):
        return ReadResult(
            request_id, "public/a\nb", "/fixture/public/a\nb",
            PolicyDecision.ALLOWED, ExecutionStatus.SUCCEEDED, "ok",
            b"synthetic", False, authorized_roots=("/fixture/public",),
        )

    def test_exclusive_creation_flushed_record_and_closed_reuse(self):
        with JsonlAuditWriter(self.path) as writer:
            writer.write(build_audit_record(self.result()))
            text = self.path.read_text()
            self.assertEqual(text.count("\n"), 1)
            data = json.loads(text)
            self.assertEqual(data["original_path"], "public/a\nb")
            self.assertEqual(data["authorized_roots"], ["/fixture/public"])
            self.assertNotIn("content", data)
            with self.assertRaises(AuditWriteError):
                JsonlAuditWriter(self.path)
            self.assertEqual(self.path.read_text(), text)
        writer.close()
        with self.assertRaises(AuditWriteError):
            writer.ensure_available()

    def test_failed_write_prevents_later_service_calls(self):
        for mode in ("short", "flush"):
            with self.subTest(mode=mode):
                writer = object.__new__(JsonlAuditWriter)
                writer._failed = False
                stream = Mock()
                stream.closed = False
                stream.write.side_effect = lambda line: 1 if mode == "short" else len(line)
                if mode == "flush":
                    stream.flush.side_effect = OSError("synthetic disk failure")
                writer._stream = stream
                service = Mock()
                service.read.side_effect = lambda request: self.result(request.request_id)
                tool = FileTools(service, writer)
                with self.assertRaises(AuditWriteError):
                    tool.read_file("public/a\nb")
                service.read.assert_called_once()
                writes = stream.write.call_count
                with self.assertRaises(AuditWriteError):
                    tool.read_file("public/other")
                service.read.assert_called_once()
                self.assertEqual(stream.write.call_count, writes)

    def test_tool_result_matches_audit_without_exposing_roots(self):
        service = Mock()
        service.read.side_effect = lambda request: self.result(request.request_id)
        with JsonlAuditWriter(self.path) as writer:
            output = FileTools(service, writer).read_file("public/a\nb")
            record = json.loads(self.path.read_text())
            self.assertEqual(output["request_id"], record["request_id"])
            self.assertNotIn("authorized_roots", output)
            self.assertNotIn("resolved_path", output)


if __name__ == "__main__":
    unittest.main()
