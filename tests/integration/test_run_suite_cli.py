"""Real suite CLI against isolated synthetic filesystem fixtures on Linux."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "linux", "Requires Linux enforcement")
class RunSuiteCLITests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.workspace = self.root / "workspace"
        (self.workspace / "public").mkdir(parents=True)
        (self.workspace / "secret").mkdir()
        (self.workspace / "public/readme.txt").write_text("hello")
        (self.workspace / "secret/token.txt").write_text("SYNTHETIC-ONLY")
        self.repo = Path(__file__).resolve().parents[2]
        self.case_file = self.root / "cases.json"
        self.document = json.loads((self.repo / "examples/filesystem-cases.json").read_text())

    def run_cli(self, workspace=None, *, report_path=None):
        self.case_file.write_text(json.dumps(self.document))
        return subprocess.run(
            [sys.executable, "-B", "-m", "attack_runner.run_suite",
             "--case-file", str(self.case_file), "--workspace", str(workspace or self.workspace),
             "--allowed-root", "public"] + (
                 ["--report-file", str(report_path)] if report_path is not None else []),
            cwd=self.repo, env={**os.environ, "TMPDIR": str(self.root)},
            capture_output=True, text=True, timeout=40,
        )

    def test_example_passes_and_output_excludes_content(self):
        process = self.run_cli()
        self.assertEqual(process.returncode, 0, process.stderr)
        rows = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual([r["record_type"] for r in rows],
                         ["case.verdict", "case.verdict", "suite.summary"])
        self.assertEqual([r["status"] for r in rows[:-1]], ["passed", "passed"])
        self.assertEqual([r["findings"][0]["status"] for r in rows[:-1]],
                         ["not_detected", "detected"])
        self.assertEqual(rows[-1], dict(record_type="suite.summary", total=2,
                                       passed=2, failed=0, detection_errors=0, successful=True))
        for text in ("SYNTHETIC-ONLY", "content_base64", "authorized_roots"):
            self.assertNotIn(text, process.stdout)

    def test_unmet_expectation_exits_one(self):
        self.document["cases"][1]["expectation"]["detection_status"] = "not_detected"
        process = self.run_cli()
        self.assertEqual(process.returncode, 1, process.stderr)
        rows = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(rows[1]["status"], "failed")
        self.assertTrue(rows[1]["mismatches"])
        self.assertFalse(rows[-1]["successful"])

    def test_bad_case_file_exits_two_before_audit_setup(self):
        self.document["cases"][1]["case_id"] = self.document["cases"][0]["case_id"]
        process = self.run_cli()
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertNotIn('"audit_file"', process.stderr)

    def test_missing_workspace_exits_three_without_summary(self):
        process = self.run_cli(self.root / "missing")
        self.assertEqual(process.returncode, 3, process.stderr)
        self.assertEqual(process.stdout, "")
        message = json.loads(process.stderr.splitlines()[-1])
        self.assertEqual(message["error"], "batch_aborted")

    def test_saved_report_matches_stdout_audit_and_expectations(self):
        report_path = self.root / "report.json"
        process = self.run_cli(report_path=report_path)
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(report_path.read_text())
        rows = [json.loads(line) for line in process.stdout.splitlines()]
        metadata = json.loads(process.stderr.splitlines()[0])
        self.assertEqual(report["run_id"], metadata["run_id"])
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["run_status"], "completed")
        summary = dict(rows[-1])
        del summary["record_type"]
        self.assertEqual(report["summary"], summary)
        audit = [json.loads(line) for line in Path(metadata["audit_file"]).read_text().splitlines()]
        self.assertEqual([c["request_id"] for c in report["cases"]],
                         [record["request_id"] for record in audit])
        for case, output, source in zip(report["cases"], rows[:-1], self.document["cases"]):
            self.assertEqual(case["case_id"], source["case_id"])
            self.assertEqual(case["path"], source["path"])
            self.assertEqual(case["expected"], source["expectation"])
            self.assertEqual(case["verdict"]["status"], output["status"])
            self.assertEqual(case["verdict"]["mismatches"], output["mismatches"])
            self.assertEqual(case["findings"], output["findings"])
            self.assertEqual(case["actual"]["policy_decision"], output["actual"]["policy_decision"])
        raw = report_path.read_text()
        self.assertNotIn("SYNTHETIC-ONLY", raw)
        self.assertNotIn("aGVsbG8=", raw)
        for key in ("content_base64", "resolved_path", "authorized_roots"):
            self.assertNotIn(json.dumps(key) + ":", raw)

    def test_failed_expectation_still_saves_report(self):
        self.document["cases"][1]["expectation"]["detection_status"] = "not_detected"
        report_path = self.root / "failed.json"
        process = self.run_cli(report_path=report_path)
        self.assertEqual(process.returncode, 1, process.stderr)
        report = json.loads(report_path.read_text())
        self.assertFalse(report["summary"]["successful"])
        self.assertEqual(report["summary"]["failed"], 1)
        self.assertTrue(report["cases"][1]["verdict"]["mismatches"])

    def test_existing_report_is_preserved_and_exit_is_three(self):
        report_path = self.root / "existing.json"
        original = b'{"previous": true}\n'
        report_path.write_bytes(original)
        process = self.run_cli(report_path=report_path)
        self.assertEqual(process.returncode, 3, process.stderr)
        self.assertEqual(report_path.read_bytes(), original)
        self.assertTrue(json.loads(process.stdout.splitlines()[-1])["successful"])
        error = json.loads(process.stderr.splitlines()[-1])
        self.assertEqual(error["error"], "report_write_failed")

    def test_interrupted_run_does_not_create_completed_report(self):
        report_path = self.root / "incomplete.json"
        process = self.run_cli(self.root / "missing", report_path=report_path)
        self.assertEqual(process.returncode, 3, process.stderr)
        self.assertFalse(report_path.exists())
        self.assertEqual(process.stdout, "")
