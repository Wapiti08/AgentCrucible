"""Portable service tests using synthetic bytes and an in-memory platform.

Run: uv run --locked python -m unittest discover -s tests/unit -v
"""

from contextlib import contextmanager
from hashlib import sha256
from io import BytesIO
import unittest

from mcp_servers.filesystem_server.models import (
    ExecutionStatus,
    FileServiceConfig,
    PolicyDecision,
    ReadRequest,
)
from mcp_servers.filesystem_server.platforms.base import (
    FileIdentity,
    FilePlatform,
    OpenedFile,
    PlatformErrorCode,
    PlatformRequestError,
)
from mcp_servers.filesystem_server.service import FileService


class RecordingStream(BytesIO):
    def __init__(self, content, read_error=None):
        super().__init__(content)
        self.read_error = read_error
        self.requested_sizes = []
        self.consumed_before_error = 0

    def read(self, size=-1):
        self.requested_sizes.append(size)
        if self.read_error is not None:
            self.consumed_before_error = len(super().read(2))
            raise self.read_error
        return super().read(size)


class MemoryPlatform(FilePlatform):
    def __init__(self, content=b"", *, open_error=None, read_error=None,
                 cleanup_error=None):
        super().__init__(FileServiceConfig("/fixture", ("public",), 4))
        self.content = content
        self.open_error = open_error
        self.read_error = read_error
        self.cleanup_error = cleanup_error
        self.streams = []

    @contextmanager
    def open_read(self, request):
        self._ensure_open()
        if self.open_error is not None:
            raise self.open_error
        stream = RecordingStream(self.content, self.read_error)
        self.streams.append(stream)
        with stream:
            yield OpenedFile(FileIdentity(1, 2), stream, "/fixture/public/sample")
        if self.cleanup_error is not None:
            raise self.cleanup_error

    def _close_resources(self):
        pass


class FileServiceTests(unittest.TestCase):
    def setUp(self):
        self.request = ReadRequest("request-1", "public/sample")

    def assert_no_content(self, result):
        self.assertIsNone(result.content)
        self.assertIsNone(result.truncated)
        self.assertIsNone(result.content_sha256)
        self.assertEqual(result.returned_bytes, 0)

    def test_success_boundaries_and_returned_content_digest(self):
        for content in (b"", b"ab", b"abcd", b"abcde", b"\x00\xffabcdef"):
            with self.subTest(size=len(content)):
                platform = MemoryPlatform(content)
                result = FileService(platform).read(self.request)
                self.assertEqual(result.content, content[:4])
                self.assertEqual(result.truncated, len(content) > 4)
                self.assertEqual(result.content_sha256, sha256(content[:4]).hexdigest())
                self.assertEqual(result.returned_bytes, min(len(content), 4))
                self.assertIs(result.policy_decision, PolicyDecision.ALLOWED)
                self.assertIs(result.execution_status, ExecutionStatus.SUCCEEDED)
                self.assertEqual(result.request_id, self.request.request_id)
                self.assertEqual(result.original_path, self.request.original_path)
                self.assertEqual(result.resolved_path, "/fixture/public/sample")
                self.assertEqual(platform.streams[0].requested_sizes, [5])
                self.assertTrue(platform.streams[0].closed)
                self.assertFalse(platform.closed)

    def test_platform_errors_preserve_policy_and_discard_content(self):
        cases = (
            (PolicyDecision.BLOCKED, PlatformErrorCode.OUTSIDE_AUTHORIZED_ROOTS),
            (PolicyDecision.NOT_EVALUATED, PlatformErrorCode.FILE_NOT_FOUND),
            (PolicyDecision.ERROR, PlatformErrorCode.AUTHORIZATION_STATE_UNVERIFIABLE),
            (PolicyDecision.ALLOWED, PlatformErrorCode.PERMISSION_DENIED),
        )
        for policy, code in cases:
            with self.subTest(policy=policy):
                error = PlatformRequestError(code, policy_decision=policy,
                                             resolved_path="/fixture/public/sample")
                platform = MemoryPlatform(open_error=error)
                result = FileService(platform).read(self.request)
                self.assertIs(result.policy_decision, policy)
                expected = (ExecutionStatus.FAILED if policy is PolicyDecision.ALLOWED
                            else ExecutionStatus.NOT_STARTED)
                self.assertIs(result.execution_status, expected)
                self.assertEqual(result.reason, code.value)
                self.assertEqual(result.resolved_path, error.resolved_path)
                self.assertEqual(result.request_id, self.request.request_id)
                self.assert_no_content(result)
                self.assertEqual(platform.streams, [])
                self.assertFalse(platform.closed)

    def test_partial_read_failure_discards_bytes_and_closes_stream(self):
        platform = MemoryPlatform(b"synthetic", read_error=OSError("private details"))
        result = FileService(platform).read(self.request)
        self.assertIs(result.policy_decision, PolicyDecision.ALLOWED)
        self.assertIs(result.execution_status, ExecutionStatus.FAILED)
        self.assertEqual(result.reason, PlatformErrorCode.IO_ERROR.value)
        self.assertEqual(result.resolved_path, "/fixture/public/sample")
        self.assert_no_content(result)
        self.assertEqual(platform.streams[0].consumed_before_error, 2)
        self.assertTrue(platform.streams[0].closed)

    def test_service_reuses_borrowed_platform(self):
        platform = MemoryPlatform(b"abc")
        service = FileService(platform)
        for request_id in ("one", "two"):
            result = service.read(ReadRequest(request_id, "public/sample"))
            self.assertEqual(result.request_id, request_id)
            self.assertEqual(result.content, b"abc")
        self.assertEqual(len(platform.streams), 2)
        self.assertTrue(all(stream.closed for stream in platform.streams))
        self.assertFalse(platform.closed)

    def test_unexpected_errors_and_interrupts_propagate(self):
        for error in (ValueError("programming error"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                platform = MemoryPlatform(b"abc", read_error=error)
                with self.assertRaises(type(error)) as caught:
                    FileService(platform).read(self.request)
                self.assertIs(caught.exception, error)
                self.assertTrue(platform.streams[0].closed)

    def test_cleanup_failure_propagates_instead_of_returning_success(self):
        # Current contract: cleanup failures propagate; no success is returned.
        error = OSError("synthetic cleanup failure")
        platform = MemoryPlatform(b"abc", cleanup_error=error)
        with self.assertRaises(OSError) as caught:
            FileService(platform).read(self.request)
        self.assertIs(caught.exception, error)
        self.assertTrue(platform.streams[0].closed)


if __name__ == "__main__":
    unittest.main()
