"""Report content, exclusive creation and CLI persistence contracts."""
import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from unittest.mock import AsyncMock, patch

from test_suite import audited, expectation, finding
from attack_runner.expectations import evaluate_file_read
from attack_runner.suite import FileReadTestResult
from attack_runner.run_suite import main
from detectors.engine import DetectionStatus
from reports.json_report import build_suite_report, write_suite_report, ReportWriteError


def result(status=DetectionStatus.DETECTED):
    item = audited()
    findings = (finding(status),)
    expected = expectation()
    return FileReadTestResult(item, findings, evaluate_file_read(item, findings, expected), expected)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.directory / "report.json"

    def test_report_preserves_expected_actual_and_verdict(self):
        report = build_suite_report((result(),), run_id="run-1")
        self.assertEqual(report["run_id"], "run-1")
        self.assertEqual(report["run_status"], "completed")
        self.assertTrue(report["summary"]["successful"])
        case = report["cases"][0]
        self.assertEqual(case["expected"]["detection_status"], "detected")
        self.assertEqual(case["actual"]["policy_decision"], "blocked")
        self.assertEqual(case["verdict"]["status"], "passed")
        for key in ("content_base64", "authorized_roots", "resolved_path"):
            self.assertNotIn(json.dumps(key) + chr(58), json.dumps(report))

    def test_failure_report_and_run_id_validation(self):
        report = build_suite_report((result(DetectionStatus.NOT_EVALUATED),), run_id="run-2")
        self.assertFalse(report["summary"]["successful"])
        self.assertTrue(report["cases"][0]["verdict"]["mismatches"])
        for run_id in ("", " ", " id", None):
            with self.subTest(run_id=run_id), self.assertRaises((TypeError, ValueError)):
                build_suite_report((), run_id=run_id)

    def test_roundtrip_and_no_overwrite(self):
        report = build_suite_report((result(),), run_id="run-1")
        write_suite_report(self.path, report)
        self.assertEqual(json.loads(self.path.read_text()), report)
        original = self.path.read_bytes()
        with self.assertRaises(ReportWriteError):
            write_suite_report(self.path, {"replacement": True})
        self.assertEqual(self.path.read_bytes(), original)

    def test_serialization_and_missing_parent_fail(self):
        for value in (object(), float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ReportWriteError):
                write_suite_report(self.path, {"bad": value})
            self.assertFalse(self.path.exists())
        with self.assertRaises(ReportWriteError):
            write_suite_report(self.directory / "missing/report.json", {})

    def test_cli_persists_pass_failure_and_error_reports(self):
        example = Path(__file__).resolve().parents[2] / "examples/filesystem-cases.json"
        args = ["--case-file", str(example), "--workspace", "/fixtures",
                "--allowed-root", "public", "--report-file", str(self.path)]
        for status, expected_code in ((DetectionStatus.DETECTED, 0),
                                      (DetectionStatus.NOT_EVALUATED, 1),
                                      (DetectionStatus.ERROR, 3)):
            with self.subTest(status=status), patch(
                "attack_runner.run_suite.run_file_suite", AsyncMock(return_value=(result(status),))
            ), patch("attack_runner.run_suite.create_audit_path",
                     return_value=self.directory / "audit.jsonl"), redirect_stdout(StringIO()), redirect_stderr(
                         StringIO()) as err:
                self.assertEqual(main(args), expected_code)
                report = json.loads(self.path.read_text())
                self.assertEqual(report["run_id"], json.loads(err.getvalue())["run_id"])
                self.path.unlink()

    def test_cli_write_failure_preserves_output_and_old_file(self):
        self.path.write_text("old")
        example = Path(__file__).resolve().parents[2] / "examples/filesystem-cases.json"
        with patch("attack_runner.run_suite.run_file_suite", AsyncMock(return_value=(result(),))), patch(
            "attack_runner.run_suite.create_audit_path", return_value=self.directory / "audit.jsonl"
        ), redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
            self.assertEqual(main(["--case-file", str(example), "--workspace", "/fixtures",
                                   "--report-file", str(self.path)]), 3)
        self.assertEqual(self.path.read_text(), "old")
        self.assertIn('"case.verdict"', out.getvalue())
        self.assertEqual(json.loads(err.getvalue().splitlines()[-1])["error"], "report_write_failed")
