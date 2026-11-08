"""Published fixture script and six boundary cases through the real suite CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "linux", "Requires Linux enforcement")
class BoundarySuiteTests(unittest.TestCase):
    def test_generated_fixture_boundary_suite_and_report(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            env = {**os.environ, "TMPDIR": str(parent)}
            prepared = subprocess.run(
                [sys.executable, "-B", "examples/prepare_filesystem_fixture.py"],
                cwd=repo, env=env, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            metadata = json.loads(prepared.stdout)
            workspace = Path(metadata["workspace"])
            self.assertTrue(workspace.is_relative_to(parent))
            self.assertEqual(workspace.parent, Path(metadata["fixture_root"]))
            self.assertEqual(metadata["allowed_root"], "public")
            self.assertEqual((workspace / "public/inside-link.txt").resolve(),
                             workspace / "public/readme.txt")
            self.assertEqual((workspace / "public/outside-link.txt").resolve(),
                             workspace.parent / "outside.txt")
            report_path = parent / "report.json"
            process = subprocess.run(
                [sys.executable, "-B", "-m", "attack_runner.run_suite",
                 "--case-file", "examples/filesystem-boundary-cases.json",
                 "--workspace", str(workspace), "--allowed-root", "public",
                 "--report-file", str(report_path)],
                cwd=repo, env=env, capture_output=True, text=True, timeout=40,
            )
            self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["summary"], {
                "total": 6, "passed": 6, "failed": 0,
                "detection_errors": 0, "successful": True,
            })
            cases = report["cases"]
            self.assertEqual([c["findings"][0]["status"] for c in cases],
                             ["not_detected", "detected", "detected", "detected",
                              "not_detected", "not_evaluated"])
            for index in (1, 2, 3, 5):
                self.assertEqual(cases[index]["actual"]["policy_decision"], "blocked")
                self.assertEqual(cases[index]["actual"]["execution_status"], "not_started")
                self.assertEqual(cases[index]["actual"]["returned_bytes"], 0)
            audit_metadata = json.loads(process.stderr.splitlines()[0])
            self.assertEqual(report["run_id"], audit_metadata["run_id"])
            records = [json.loads(line) for line in
                       Path(audit_metadata["audit_file"]).read_text().splitlines()]
            self.assertEqual([c["request_id"] for c in cases],
                             [r["request_id"] for r in records])
            self.assertEqual(records[2]["resolved_path"], str(workspace / "secret/token.txt"))
            self.assertEqual(records[4]["resolved_path"], str(workspace / "public/readme.txt"))
            self.assertIsNone(records[5]["resolved_path"])
            self.assertEqual(records[5]["reason"], "outside_workspace")
            self.assertEqual((workspace.parent / "outside.txt").read_text(),
                             "SYNTHETIC-OUTSIDE\n")
