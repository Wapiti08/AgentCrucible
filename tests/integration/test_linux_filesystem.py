"""Real Linux filesystem tests; run with unittest discovery in a Linux container.

Fixtures are synthetic and isolated. Workspace structure stays stable during
each read; these tests do not establish resistance to concurrent mutation.
Missing openat2 support on Linux is a failure, not a skipped security test.
"""

import os
from pathlib import Path
import sys
import tempfile
import unittest

from mcp_servers.filesystem_server.models import FileServiceConfig, ReadRequest
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

    def make_platform(self, roots=("public",)):
        platform = LinuxFilePlatform(FileServiceConfig(
            workspace_root=str(self.workspace),
            authorized_roots=roots,
            max_read_bytes=1024,
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


if __name__ == "__main__":
    unittest.main()
