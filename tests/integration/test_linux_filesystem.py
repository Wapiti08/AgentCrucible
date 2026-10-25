"""Real Linux filesystem tests; run with unittest discovery in a Linux container.

Fixtures are synthetic and isolated. Workspace structure stays stable during
each read; these tests do not establish resistance to concurrent mutation.
Missing openat2 support on Linux is a failure, not a skipped security test.
"""

import os
from hashlib import sha256
from pathlib import Path
import sys
import tempfile
import unittest

from mcp_servers.filesystem_server.models import (
    ExecutionStatus, FileServiceConfig, PolicyDecision, ReadRequest,
)
from mcp_servers.filesystem_server.service import FileService
from mcp_servers.filesystem_server.platforms.base import (
    PlatformErrorCode as Code,
    PlatformInitializationError,
    PlatformRequestError,
)
from mcp_servers.filesystem_server.platforms.linux import LinuxFilePlatform


@unittest.skipUnless(sys.platform == "linux", "Requires real Linux syscalls and /proc")
class LinuxFilesystemTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agentic-fs-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / "workspace"
        self.public = self.workspace / "public"
        self.public.mkdir(parents=True)
        (self.workspace / "secret").mkdir()
        (self.workspace / "publicity").mkdir()
        self.content = b"synthetic test content\x00\xff\n"
        (self.public / "sample.bin").write_bytes(self.content)
        (self.public / "empty").write_bytes(b"")
        (self.workspace / "secret/token.txt").write_text("FAKE-TEST-TOKEN")
        (self.workspace / "publicity/file.txt").write_text("synthetic")
        (self.root / "outside.txt").write_text("synthetic outside fixture")
        self.platform = self.make_platform()

    def make_platform(self, roots=("public",), limit=1024):
        platform = LinuxFilePlatform(FileServiceConfig(
            workspace_root=str(self.workspace),
            authorized_roots=roots,
            max_read_bytes=limit,
        ))
        self.addCleanup(platform.close)
        return platform

    def fd_count(self):
        # Single-threaded tests: compare before/after, not absolute fd numbers.
        return len(os.listdir("/proc/self/fd"))

    def assert_denied(self, path, expected, platform=None):
        before = self.fd_count()
        with self.assertRaises(PlatformRequestError) as caught:
            with (platform or self.platform).open_read(ReadRequest("denied", path)):
                self.fail("Rejected request yielded a stream")
        self.assertEqual(caught.exception.code, expected)
        self.assertEqual(self.fd_count(), before, "Temporary fd leaked")

    def test_read_binary_relative_and_absolute_paths(self):
        target = self.public / "sample.bin"
        for path in ("public/sample.bin", str(target), "/" + str(target)):
            with self.subTest(path=path):
                before = self.fd_count()
                with self.platform.open_read(ReadRequest("read", path)) as opened:
                    self.assertEqual(opened.stream.tell(), 0)
                    self.assertEqual(opened.stream.read(), self.content)
                    metadata = target.stat()
                    self.assertEqual(opened.identity.device, metadata.st_dev)
                    self.assertEqual(opened.identity.inode, metadata.st_ino)
                    self.assertEqual(opened.resolved_path, str(target))
                self.assertTrue(opened.stream.closed)
                self.assertEqual(self.fd_count(), before)

    def test_empty_file(self):
        with self.platform.open_read(ReadRequest("empty", "public/empty")) as opened:
            self.assertEqual(opened.stream.read(), b"")
        self.assertTrue(opened.stream.closed)

    def test_relative_symlink_to_authorized_target(self):
        (self.workspace / "shortcut").symlink_to("public", target_is_directory=True)
        with self.platform.open_read(ReadRequest("link", "shortcut/sample.bin")) as opened:
            self.assertEqual(opened.stream.read(), self.content)
            self.assertEqual(opened.resolved_path, str(self.public / "sample.bin"))

    def test_outside_authorized_roots_and_prefix_collision(self):
        for path in ("secret/token.txt", "public/../secret/token.txt", "publicity/file.txt"):
            with self.subTest(path=path):
                self.assert_denied(path, Code.OUTSIDE_AUTHORIZED_ROOTS)

    def test_symlink_to_unauthorized_target(self):
        (self.public / "link").symlink_to("../secret/token.txt")
        self.assert_denied("public/link", Code.OUTSIDE_AUTHORIZED_ROOTS)

    def test_workspace_escape(self):
        (self.public / "escape").symlink_to("../../outside.txt")
        for path in ("../outside.txt", str(self.root / "outside.txt"), "public/escape"):
            with self.subTest(path=path):
                self.assert_denied(path, Code.OUTSIDE_WORKSPACE)

    def test_absolute_symlink_is_rejected_even_to_authorized_file(self):
        (self.public / "absolute").symlink_to(self.public / "sample.bin")
        self.assert_denied("public/absolute", Code.OUTSIDE_WORKSPACE)

    def test_invalid_missing_and_nonregular_targets(self):
        os.mkfifo(self.public / "fifo")
        cases = [("", Code.INVALID_PATH), ("public/\x00", Code.INVALID_PATH),
                 ("public/missing", Code.FILE_NOT_FOUND),
                 ("public/sample.bin/child", Code.INVALID_PATH),
                 ("public", Code.NOT_REGULAR_FILE),
                 ("public/fifo", Code.NOT_REGULAR_FILE)]
        for path, code in cases:
            with self.subTest(path=path):
                self.assert_denied(path, code)

    def test_symlink_loop(self):
        (self.public / "loop").symlink_to("loop")
        self.assert_denied("public/loop", Code.AUTHORIZATION_STATE_UNVERIFIABLE)

    def test_empty_allowlist(self):
        self.assert_denied("public/sample.bin", Code.NO_AUTHORIZED_ROOTS,
                           self.make_platform(()))

    def test_caller_exception_is_preserved_and_resources_closed(self):
        original = OSError("synthetic caller failure")
        before = self.fd_count()
        with self.assertRaises(OSError) as caught:
            with self.platform.open_read(ReadRequest("caller", "public/sample.bin")) as opened:
                raise original
        self.assertIs(caught.exception, original)
        self.assertTrue(opened.stream.closed)
        self.assertEqual(self.fd_count(), before)

    def test_close_is_idempotent_and_prevents_reuse(self):
        self.platform.close()
        before = self.fd_count()
        self.platform.close()
        self.assertEqual(self.fd_count(), before)
        with self.assertRaises(RuntimeError):
            with self.platform.open_read(ReadRequest("closed", "public/sample.bin")):
                self.fail("Closed platform accepted a request")

    def test_partial_initialization_releases_directories(self):
        before = self.fd_count()
        with self.assertRaises(PlatformInitializationError):
            self.make_platform(("public", "missing-root"))
        self.assertEqual(self.fd_count(), before)

    def test_service_read_boundaries_and_digest(self):
        platform = self.make_platform(limit=4)
        service = FileService(platform)
        target = self.public / "boundary.bin"
        for content in (b"", b"ab", b"abcd", b"abcde", b"\x00\xffabcdef"):
            with self.subTest(size=len(content)):
                target.write_bytes(content)
                before = self.fd_count()
                result = service.read(ReadRequest("boundary", "public/boundary.bin"))
                self.assertIs(result.policy_decision, PolicyDecision.ALLOWED)
                self.assertIs(result.execution_status, ExecutionStatus.SUCCEEDED)
                self.assertEqual(result.content, content[:4])
                self.assertEqual(result.truncated, len(content) > 4)
                self.assertEqual(result.content_sha256, sha256(content[:4]).hexdigest())
                self.assertEqual(result.returned_bytes, min(len(content), 4))
                self.assertEqual(result.resolved_path, str(target))
                self.assertEqual(result.request_id, "boundary")
                self.assertEqual(result.original_path, "public/boundary.bin")
                self.assertEqual(self.fd_count(), before)
                self.assertFalse(platform.closed)

    def assert_service_failure(self, service, path, code, policy):
        before = self.fd_count()
        result = service.read(ReadRequest("failure", path))
        self.assertEqual(result.request_id, "failure")
        self.assertEqual(result.original_path, path)
        self.assertEqual(result.reason, code.value)
        self.assertIs(result.policy_decision, policy)
        self.assertIs(result.execution_status, ExecutionStatus.NOT_STARTED)
        self.assertIsNone(result.content)
        self.assertIsNone(result.truncated)
        self.assertIsNone(result.content_sha256)
        self.assertEqual(result.returned_bytes, 0)
        self.assertEqual(self.fd_count(), before)
        return result

    def test_service_policy_rejections(self):
        service = FileService(self.platform)
        for path, code in (
            ("secret/token.txt", Code.OUTSIDE_AUTHORIZED_ROOTS),
            ("public/../secret/token.txt", Code.OUTSIDE_AUTHORIZED_ROOTS),
            ("../outside.txt", Code.OUTSIDE_WORKSPACE),
            (str(self.root / "outside.txt"), Code.OUTSIDE_WORKSPACE),
        ):
            with self.subTest(path=path):
                self.assert_service_failure(service, path, code, PolicyDecision.BLOCKED)
        empty = FileService(self.make_platform(()))
        self.assert_service_failure(empty, "public/sample.bin", Code.NO_AUTHORIZED_ROOTS,
                                    PolicyDecision.BLOCKED)

    def test_service_missing_and_invalid_inputs_are_not_evaluated(self):
        service = FileService(self.platform)
        for path, code in (("public/missing", Code.FILE_NOT_FOUND),
                           ("", Code.INVALID_PATH), ("public/\x00", Code.INVALID_PATH)):
            with self.subTest(path=path):
                result = self.assert_service_failure(service, path, code,
                                                     PolicyDecision.NOT_EVALUATED)
                self.assertIsNone(result.resolved_path)

    def test_service_symlink_resolves_to_authorized_target(self):
        (self.workspace / "shortcut").symlink_to("public", target_is_directory=True)
        service = FileService(self.platform)
        before = self.fd_count()
        result = service.read(ReadRequest("link", "shortcut/sample.bin"))
        self.assertIs(result.execution_status, ExecutionStatus.SUCCEEDED)
        self.assertIs(result.policy_decision, PolicyDecision.ALLOWED)
        self.assertEqual(result.content, self.content)
        self.assertFalse(result.truncated)
        self.assertEqual(result.resolved_path, str(self.public / "sample.bin"))
        self.assertEqual(self.fd_count(), before)

    def test_service_can_read_after_rejected_request(self):
        service = FileService(self.platform)
        self.assert_service_failure(service, "secret/token.txt",
                                    Code.OUTSIDE_AUTHORIZED_ROOTS, PolicyDecision.BLOCKED)
        result = service.read(ReadRequest("next", "public/sample.bin"))
        self.assertIs(result.execution_status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(result.content, self.content)
        self.assertFalse(self.platform.closed)


if __name__ == "__main__":
    unittest.main()
