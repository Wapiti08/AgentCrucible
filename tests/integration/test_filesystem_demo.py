"""One-command public demonstration through the real Linux MCP service."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "linux", "Requires Linux enforcement")
class FilesystemDemoIntegrationTests(unittest.TestCase):
    def test_demo_retains_report_and_is_repeatable(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            reports = []
            for _ in range(2):
                process = subprocess.run(
                    [sys.executable, "-B", "-m", "examples.run_filesystem_demo"],
                    cwd=repo, env={**os.environ, "TMPDIR": temporary},
                    capture_output=True, text=True, timeout=40,
                )
                self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
                demo = json.loads(process.stderr.splitlines()[0])
                self.assertEqual(demo["mode"], "direct_mcp")
                workspace = Path(demo["workspace"])
                report_path = Path(demo["report_file"])
                self.assertTrue(report_path.is_relative_to(Path(temporary)))
                self.assertFalse(report_path.is_relative_to(workspace))
                report = json.loads(report_path.read_text())
                self.assertEqual(report["summary"]["total"], 6)
                self.assertEqual(report["summary"]["passed"], 6)
                self.assertTrue(report["summary"]["successful"])
                output = [json.loads(line) for line in process.stdout.splitlines()]
                self.assertEqual(len(output), 7)
                self.assertEqual(output[-1]["record_type"], "suite.summary")
                reports.append((report_path, report_path.read_bytes()))
            self.assertNotEqual(reports[0][0], reports[1][0])
            self.assertEqual(reports[0][0].read_bytes(), reports[0][1])
