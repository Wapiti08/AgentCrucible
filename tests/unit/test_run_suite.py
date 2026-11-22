"""Suite CLI exit codes and failure output."""
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from attack_runner.run_suite import main
from attack_runner.evidence.audit_reader import AuditReadError
from attack_runner.evidence.audit_match import AuditMatchError
from attack_runner.execution.batch import BatchAbortedError
from attack_runner.execution.suite import SuiteSummary


class RunSuiteTests(unittest.TestCase):
    def setUp(self):
        example = Path(__file__).resolve().parents[2] / "examples/filesystem-cases.json"
        self.args = ["--case-file", str(example), "--workspace", "/fixtures",
                     "--allowed-root", "public"]
        self.audit = self.enterContext(patch("attack_runner.run_suite.create_audit_path",
                                            return_value=Path("/audit/events.jsonl")))

    def test_summary_exit_codes_and_error_priority(self):
        for summary, code in (
            (SuiteSummary(2, 2, 0, 0), 0),
            (SuiteSummary(2, 1, 1, 0), 1),
            (SuiteSummary(2, 2, 0, 1), 3),
            (SuiteSummary(2, 1, 1, 1), 3),
        ):
            with self.subTest(summary=summary), patch(
                "attack_runner.run_suite.run_file_suite", AsyncMock(return_value=())
            ) as suite, patch("attack_runner.run_suite.summarize_suite", return_value=summary), patch(
                "attack_runner.run_suite.print_suite_results"
            ) as output, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(main(self.args), code)
                suite.assert_awaited_once()
                self.assertEqual(suite.await_args.kwargs["audit_path"], Path("/audit/events.jsonl"))
                output.assert_called_once_with((), summary)

    def test_operational_errors_do_not_print_normal_summary(self):
        failures = [
            AuditReadError("bad audit"), AuditMatchError("missing record"),
            BatchAbortedError(phase="call", failed_case=None, completed_results=()),
        ]
        for error in failures:
            with self.subTest(error=error), patch(
                "attack_runner.run_suite.run_file_suite", AsyncMock(side_effect=error)
            ), patch("attack_runner.run_suite.print_suite_results") as output, redirect_stdout(
                StringIO()
            ) as stdout, redirect_stderr(StringIO()):
                self.assertEqual(main(self.args), 3)
                output.assert_not_called()
                self.assertEqual(stdout.getvalue(), "")

    def test_invalid_inputs_prevent_execution(self):
        for extra in (["--max-read-bytes", "0"], ["--case-file", "/missing/cases.json"]):
            with self.subTest(extra=extra), patch("attack_runner.run_suite.run_file_suite") as suite:
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as caught:
                    main(self.args + extra)
                self.assertEqual(caught.exception.code, 2)
                suite.assert_not_called()
        self.audit.assert_not_called()

    def test_audit_setup_failure_prevents_execution(self):
        self.audit.side_effect = OSError("synthetic failure")
        with patch("attack_runner.run_suite.run_file_suite") as suite, redirect_stderr(StringIO()):
            self.assertEqual(main(self.args), 3)
            suite.assert_not_called()
