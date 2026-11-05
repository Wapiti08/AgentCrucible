"""CLI parsing and output contracts without launching MCP subprocesses."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from attack_runner.batch import BatchAbortedError, FileReadCase, FileReadCaseResult
from attack_runner.mcp_models import FileReadResponse
from attack_runner.run_files import main, parse_inputs


class RunFilesTests(unittest.TestCase):
    def setUp(self):
        self.audit_path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "events.jsonl"
        self.audit_setup = self.enterContext(patch(
            "attack_runner.run_files.create_audit_path", return_value=self.audit_path,
        ))
        self.args = ["--workspace", "/fixture", "--path", "secret/a", "--path", "public/b"]
        response = FileReadResponse(
            request_id="request-1", policy_decision="blocked",
            execution_status="not_started", reason="outside_authorized_roots",
            content_base64=None, returned_bytes=0, truncated=None, content_sha256=None,
        )
        self.completed = (FileReadCaseResult("case-1", "secret/a", response),)
        self.write_audit()

    def write_audit(self, path="secret/a"):
        self.audit_path.write_text(json.dumps({
            "schema_version": 1, "request_id": "request-1",
            "original_path": path, "resolved_path": None,
            "authorized_roots": [], "policy_decision": "blocked",
            "execution_status": "not_started", "reason": "outside_authorized_roots",
        }) + "\n", encoding="utf-8")

    def test_parse_order_defaults_and_empty_attack_path(self):
        config, cases = parse_inputs(self.args + ["--path", ""])
        self.assertEqual(config.authorized_roots, ())
        self.assertEqual(config.max_read_bytes, 65536)
        self.assertEqual([(c.case_id, c.path) for c in cases],
                         [("case-1", "secret/a"), ("case-2", "public/b"), ("case-3", "")])
        config, _ = parse_inputs(self.args + ["--allowed-root", "public",
                                             "--allowed-root", "shared", "--max-read-bytes", "4"])
        self.assertEqual(config.authorized_roots, ("public", "shared"))
        self.assertEqual(config.max_read_bytes, 4)

    def test_invalid_arguments_exit_two_without_starting_batch(self):
        for args in (["--path", "a"], ["--workspace", "/fixture"],
                     self.args + ["--max-read-bytes", "0"],
                     self.args + ["--max-read-bytes", "not-an-int"]):
            with self.subTest(args=args), patch("attack_runner.run_files.run_file_batch") as batch:
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as caught:
                    main(args)
                self.assertEqual(caught.exception.code, 2)
                batch.assert_not_called()

    def test_blocked_result_completes_normally(self):
        out, err = StringIO(), StringIO()
        batch = AsyncMock(return_value=self.completed)
        with patch("attack_runner.run_files.run_file_batch", batch), redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(main(self.args), 0)
        self.assertEqual(json.loads(err.getvalue()), {"audit_file": str(self.audit_path)})
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        row, finding = rows
        self.assertEqual(finding["status"], "not_evaluated")
        self.assertEqual(finding["record_type"], "detector.finding")
        self.assertEqual(finding["request_id"], row["request_id"])
        self.assertEqual(row["policy_decision"], "blocked")
        self.assertEqual(row["request_id"], "request-1")
        self.assertNotIn("content_base64", row)
        batch.assert_awaited_once()
        self.assertEqual(batch.await_args.kwargs, {"audit_path": self.audit_path})
        cases, config = batch.await_args.args
        self.assertEqual([c.path for c in cases], ["secret/a", "public/b"])
        self.assertEqual(config.workspace_root, "/fixture")

    def test_aborted_batch_preserves_results_and_reports_phase(self):
        for phase in ("connect", "call", "close"):
            with self.subTest(phase=phase):
                completed = () if phase == "connect" else self.completed
                failed_case = FileReadCase("case-2", "public/b") if phase == "call" else None
                error = BatchAbortedError(phase=phase, failed_case=failed_case,
                                          completed_results=completed)
                out, err = StringIO(), StringIO()
                with patch("attack_runner.run_files.run_file_batch", AsyncMock(side_effect=error)), redirect_stdout(out), redirect_stderr(err):
                    self.assertEqual(main(self.args), 1)
                rows = [json.loads(line) for line in out.getvalue().splitlines()]
                self.assertEqual(len(rows), len(completed))
                if rows:
                    self.assertEqual(rows[0]["case_id"], "case-1")
                messages = [json.loads(line) for line in err.getvalue().splitlines()]
                self.assertEqual(messages[0], {"audit_file": str(self.audit_path)})
                self.assertEqual(messages[1], {
                    "error": "batch_aborted", "phase": phase,
                    "failed_case_id": "case-2" if phase == "call" else None,
                    "completed_count": len(completed),
                })

    def test_output_escapes_control_characters(self):
        path = "secret/\n\x1b[31m"
        self.write_audit(path)
        completed = (FileReadCaseResult("case-1", path, self.completed[0].response),)
        out = StringIO()
        with patch("attack_runner.run_files.run_file_batch", AsyncMock(return_value=completed)), redirect_stdout(out), redirect_stderr(StringIO()):
            self.assertEqual(main(self.args), 0)
        self.assertEqual(len(out.getvalue().splitlines()), 2)
        self.assertNotIn("\x1b", out.getvalue())
        self.assertEqual(json.loads(out.getvalue().splitlines()[0])["path"], path)

    def test_bad_audit_preserves_results_but_fails_cli(self):
        for content in ("{broken\n", "", self.audit_path.read_text().replace(
                "outside_authorized_roots", "different_reason")):
            with self.subTest(content=content):
                self.audit_path.write_text(content, encoding="utf-8")
                out, err = StringIO(), StringIO()
                with patch("attack_runner.run_files.run_file_batch",
                           AsyncMock(return_value=self.completed)), redirect_stdout(out), redirect_stderr(err):
                    self.assertEqual(main(self.args), 1)
                self.assertEqual(json.loads(out.getvalue())["request_id"], "request-1")
                self.assertEqual(json.loads(err.getvalue().splitlines()[-1])["error"],
                                 "audit_validation_failed")

    def test_detector_error_is_reported_and_exits_one(self):
        from detectors.engine import DetectionResult, DetectionStatus
        failure = DetectionResult(
            event_id="request-1:filesystem.read", rule_id="FS_PATH_OUTSIDE_SCOPE",
            status=DetectionStatus.ERROR, reason="Synthetic rule failure.",
        )
        out = StringIO()
        with patch("attack_runner.run_files.run_file_batch",
                   AsyncMock(return_value=self.completed)), patch(
                       "attack_runner.run_files.Detector") as detector, redirect_stdout(out), redirect_stderr(StringIO()):
            detector.return_value.detect.return_value = (failure,)
            self.assertEqual(main(self.args), 1)
        detector.assert_called_once()
        self.assertEqual(json.loads(out.getvalue().splitlines()[-1])["status"], "error")

    def test_audit_setup_failure_prevents_batch(self):
        self.audit_setup.side_effect = OSError("synthetic failure")
        out, err = StringIO(), StringIO()
        with patch("attack_runner.run_files.run_file_batch") as batch, redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(main(self.args), 1)
        batch.assert_not_called()
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(json.loads(err.getvalue()), {"error": "audit_setup_failed"})


if __name__ == "__main__":
    unittest.main()
