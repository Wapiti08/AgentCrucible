"""Suite orchestration with real audit parsing and detection, without MCP IO."""
import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from attack_runner.audit_events import build_file_access_event
from attack_runner.audit_match import AuditMatchError, AuditedFileRead
from attack_runner.audit_reader import AuditReadError, FileReadAuditEntry
from attack_runner.batch import BatchAbortedError, FileReadCase, FileReadCaseResult
from attack_runner.cases import FileReadTestCase, validate_test_cases
from attack_runner.expectations import FileReadExpectation, VerdictStatus, evaluate_file_read
from attack_runner.mcp_models import FileReadResponse
from attack_runner.suite import FileReadTestResult, run_file_suite, summarize_suite
from detectors.engine import DetectionResult, DetectionStatus, Detector
from detectors.rules.fs_path_traversal import FilePathOutsideScopeRule
from mcp_servers.filesystem_server.models import ExecutionStatus, FileServiceConfig, PolicyDecision


def expectation(status=DetectionStatus.DETECTED):
    return FileReadExpectation(PolicyDecision.BLOCKED, ExecutionStatus.NOT_STARTED,
                               "FS_PATH_OUTSIDE_SCOPE", status)


def audited(request_id="r1", case_id="case-1", resolved_path="/lab/secret/a"):
    response = FileReadResponse(
        request_id=request_id, policy_decision="blocked", execution_status="not_started",
        reason="outside_authorized_roots", content_base64=None, returned_bytes=0,
        truncated=None, content_sha256=None,
    )
    record = FileReadAuditEntry(
        schema_version=1, request_id=request_id, original_path="secret/a",
        resolved_path=resolved_path, authorized_roots=["/lab/public"],
        policy_decision="blocked", execution_status="not_started",
        reason="outside_authorized_roots",
    )
    return AuditedFileRead(FileReadCaseResult(case_id, "secret/a", response), record)


def finding(status=DetectionStatus.DETECTED, **changes):
    return replace(DetectionResult("r1:filesystem.read", status,
                                  "FS_PATH_OUTSIDE_SCOPE", "Synthetic finding."), **changes)


class ExpectationTests(unittest.TestCase):
    def test_match_and_multiple_mismatches(self):
        verdict = evaluate_file_read(audited(), (finding(),), expectation())
        self.assertEqual(verdict.status, VerdictStatus.PASSED)
        self.assertEqual(verdict.mismatches, ())
        wrong = replace(expectation(), policy_decision=PolicyDecision.ALLOWED,
                        execution_status=ExecutionStatus.SUCCEEDED)
        verdict = evaluate_file_read(audited(), (finding(DetectionStatus.NOT_EVALUATED),), wrong)
        self.assertEqual(verdict.status, VerdictStatus.FAILED)
        self.assertEqual(len(verdict.mismatches), 3)

    def test_missing_duplicate_unrelated_and_error_findings(self):
        for findings in ((), (finding(), finding()),
                         (finding(event_id="other"),),
                         (finding(DetectionStatus.ERROR),),
                         (finding(DetectionStatus.NOT_EVALUATED),)):
            with self.subTest(findings=findings):
                self.assertEqual(evaluate_file_read(audited(), findings, expectation()).status,
                                 VerdictStatus.FAILED)

    def test_other_rules_preserved_without_changing_target_expectation(self):
        findings = (finding(), finding(rule_id="OTHER"))
        self.assertEqual(evaluate_file_read(audited(), findings, expectation()).status,
                         VerdictStatus.PASSED)

    def test_expectation_validation(self):
        for changes, error in (
            ({"policy_decision": "blocked"}, TypeError),
            ({"execution_status": "not_started"}, TypeError),
            ({"detection_status": "detected"}, TypeError),
            ({"rule_id": 123}, TypeError),
            ({"rule_id": ""}, ValueError),
            ({"rule_id": " RULE"}, ValueError),
        ):
            with self.subTest(changes=changes), self.assertRaises(error):
                replace(expectation(), **changes)

    def test_case_validation_and_snapshot(self):
        case = FileReadTestCase(FileReadCase("case-1", ""), expectation())
        original = [case]
        snapshot = validate_test_cases(original)
        original.clear()
        self.assertEqual(snapshot, (case,))
        for cases in ([], [case, case], ["invalid"],
                      [replace(case, expectation=None)],
                      [replace(case, case=FileReadCase("", "a"))]):
            with self.subTest(cases=cases), self.assertRaises((TypeError, ValueError)):
                validate_test_cases(cases)

    def test_event_preserves_unknown_and_empty_roots(self):
        item = audited()
        for roots, expected in ((None, None), ([], ())):
            record = item.audit.model_copy(update={"authorized_roots": roots})
            event = build_file_access_event(replace(item, audit=record))
            self.assertEqual(event.data.authorized_roots, expected)


class SummaryTests(unittest.TestCase):
    def make_result(self, findings):
        item = audited()
        return FileReadTestResult(
            item, findings, evaluate_file_read(item, findings, expectation()),
        )

    def test_empty_suite_is_not_successful(self):
        summary = summarize_suite(())
        self.assertEqual((summary.total, summary.passed, summary.failed,
                          summary.detection_errors), (0, 0, 0, 0))
        self.assertFalse(summary.successful)

    def test_all_matching_cases_succeed(self):
        result = self.make_result((finding(),))
        summary = summarize_suite((result,))
        self.assertEqual((summary.total, summary.passed, summary.failed,
                          summary.detection_errors), (1, 1, 0, 0))
        self.assertTrue(summary.successful)

    def test_unmet_expectation_fails_without_detector_error(self):
        good = self.make_result((finding(),))
        bad = self.make_result((finding(DetectionStatus.NOT_EVALUATED),))
        summary = summarize_suite((good, bad))
        self.assertEqual((summary.total, summary.passed, summary.failed,
                          summary.detection_errors), (2, 1, 1, 0))
        self.assertFalse(summary.successful)

    def test_additional_rule_errors_override_passing_verdict(self):
        result = self.make_result((
            finding(),
            finding(DetectionStatus.ERROR, rule_id="OTHER_A"),
            finding(DetectionStatus.ERROR, rule_id="OTHER_B"),
        ))
        self.assertEqual(result.verdict.status, VerdictStatus.PASSED)
        summary = summarize_suite((result,))
        self.assertEqual((summary.total, summary.passed, summary.failed,
                          summary.detection_errors), (1, 1, 0, 2))
        self.assertFalse(summary.successful)


class SuiteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "audit.jsonl"
        self.config = FileServiceConfig("/lab", ("public",), 32)
        self.case = FileReadTestCase(FileReadCase("case-1", "secret/a"), expectation())
        self.item = audited()
        self.detector = Detector((FilePathOutsideScopeRule(),))

    def write_records(self, items):
        self.path.write_text("".join(item.audit.model_dump_json() + "\n" for item in items),
                             encoding="utf-8")

    async def test_full_flow_matches_expectations_by_case_id(self):
        second = audited("r2", "case-2", resolved_path=None)
        cases = (self.case, replace(self.case, case=FileReadCase("case-2", "secret/a"),
                                   expectation=expectation(DetectionStatus.NOT_EVALUATED)))
        self.write_records((self.item, second))
        batch = AsyncMock(return_value=(second.result, self.item.result))
        with patch("attack_runner.suite.run_file_batch", batch):
            results = await run_file_suite(cases, self.config, self.detector, audit_path=self.path)
        self.assertEqual([r.verdict.case_id for r in results], ["case-2", "case-1"])
        self.assertTrue(all(r.verdict.status is VerdictStatus.PASSED for r in results))
        batch.assert_awaited_once_with(tuple(c.case for c in cases), self.config,
                                      audit_path=self.path)

    async def test_invalid_cases_prevent_execution(self):
        with patch("attack_runner.suite.run_file_batch", new_callable=AsyncMock) as batch:
            with self.assertRaises(ValueError):
                await run_file_suite((self.case, self.case), self.config, self.detector,
                                     audit_path=self.path)
            batch.assert_not_awaited()

    async def test_batch_failure_preserves_exception_and_completed_results(self):
        error = BatchAbortedError(phase="call", failed_case=self.case.case,
                                 completed_results=(self.item.result,))
        with patch("attack_runner.suite.run_file_batch", AsyncMock(side_effect=error)), patch(
                "attack_runner.suite.load_audit_records") as reader:
            with self.assertRaises(BatchAbortedError) as caught:
                await run_file_suite((self.case,), self.config, self.detector, audit_path=self.path)
            self.assertIs(caught.exception, error)
            reader.assert_not_called()

    async def test_audit_errors_stop_detection(self):
        for content, error in (("{bad\n", AuditReadError), ("", AuditMatchError)):
            self.path.write_text(content, encoding="utf-8")
            detector = Mock(spec=Detector)
            with self.subTest(content=content), patch(
                    "attack_runner.suite.run_file_batch", AsyncMock(return_value=(self.item.result,))):
                with self.assertRaises(error):
                    await run_file_suite((self.case,), self.config, detector, audit_path=self.path)
                detector.detect.assert_not_called()

    async def test_rule_failure_is_visible_and_fails_expected_detection(self):
        class BrokenRule(FilePathOutsideScopeRule):
            def evaluate(self, event):
                raise RuntimeError("synthetic failure")
        self.write_records((self.item,))
        with patch("attack_runner.suite.run_file_batch", AsyncMock(return_value=(self.item.result,))):
            results = await run_file_suite((self.case,), self.config, Detector((BrokenRule(),)),
                                           audit_path=self.path)
        self.assertEqual(results[0].findings[0].status, DetectionStatus.ERROR)
        self.assertEqual(results[0].verdict.status, VerdictStatus.FAILED)


if __name__ == "__main__":
    unittest.main()
