"""Portable demo dispatch checks; real execution is covered on Linux."""
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import patch

from examples.run_filesystem_demo import main


class FilesystemDemoTests(unittest.TestCase):
    def test_unsupported_platform_does_not_create_fixture(self):
        with patch("examples.run_filesystem_demo.sys.platform", "darwin"), patch(
            "examples.run_filesystem_demo.create_fixture"
        ) as fixture, patch("examples.run_filesystem_demo.run_suite") as suite, redirect_stderr(StringIO()):
            self.assertEqual(main([]), 2)
        fixture.assert_not_called()
        suite.assert_not_called()

    def test_suite_exit_codes_are_preserved(self):
        for code in (0, 1, 2, 3):
            with self.subTest(code=code), patch("examples.run_filesystem_demo.sys.platform", "linux"), patch(
                "examples.run_filesystem_demo.create_fixture", return_value=Path("/tmp/demo/workspace")
            ), patch("examples.run_filesystem_demo.run_suite", return_value=code) as suite, redirect_stderr(StringIO()):
                self.assertEqual(main([]), code)
                args = suite.call_args.args[0]
                self.assertEqual(args[args.index("--workspace") + 1], "/tmp/demo/workspace")
                self.assertEqual(args[args.index("--report-file") + 1], "/tmp/demo/report.json")
                self.assertTrue(Path(args[args.index("--case-file") + 1]).is_file())

    def test_explicit_report_path_is_forwarded(self):
        with patch("examples.run_filesystem_demo.sys.platform", "linux"), patch(
            "examples.run_filesystem_demo.create_fixture", return_value=Path("/tmp/demo/workspace")
        ), patch("examples.run_filesystem_demo.run_suite", return_value=0) as suite, redirect_stderr(StringIO()):
            self.assertEqual(main(["--report-file", "/output/report.json"]), 0)
            args = suite.call_args.args[0]
            self.assertEqual(args[args.index("--report-file") + 1], "/output/report.json")
