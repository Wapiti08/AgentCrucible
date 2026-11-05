"""Audit evidence parsing and correlation contracts."""
import json
from pathlib import Path
import tempfile
import unittest

from attack_runner.audit_reader import AuditReadError, FileReadAuditEntry, load_audit_records
from attack_runner.audit_match import AuditMatchError, match_audit_records
from attack_runner.batch import FileReadCaseResult
from attack_runner.mcp_models import FileReadResponse


def entry(request_id="r1", **changes):
    data = dict(schema_version=1, request_id=request_id, original_path="secret/a",
                resolved_path=None, authorized_roots=[], policy_decision="blocked",
                execution_status="not_started", reason="outside_authorized_roots")
    data.update(changes)
    return data


def result(request_id="r1"):
    response = FileReadResponse(
        request_id=request_id, policy_decision="blocked", execution_status="not_started",
        reason="outside_authorized_roots", content_base64=None, returned_bytes=0,
        truncated=None, content_sha256=None)
    return FileReadCaseResult(request_id, "secret/a", response)


class AuditReaderTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "audit.jsonl"

    def test_valid_empty_and_unknown_evidence(self):
        self.path.write_text("", encoding="utf-8")
        self.assertEqual(load_audit_records(self.path), ())
        rows = [entry(), entry("r2", authorized_roots=None)]
        self.path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        records = load_audit_records(self.path)
        self.assertEqual(records[0].authorized_roots, [])
        self.assertIsNone(records[1].authorized_roots)

    def test_invalid_second_record_fails_entire_load(self):
        valid = json.dumps(entry())
        malformed = [
            "", "{}", "{broken}", "[]", valid,
            json.dumps(entry("r2", execution_status="succeeded")),
            json.dumps(entry("r2", unexpected=True)),
            '{"request_id":"r2","request_id":"r3"}',
        ]
        malformed += [json.dumps(entry("r2")).replace('"schema_version": 1',
                     '"schema_version": ' + value) for value in ("NaN", "Infinity", "-Infinity")]
        for bad in malformed:
            with self.subTest(bad=bad):
                self.path.write_text(valid + "\n" + bad + "\n", encoding="utf-8")
                with self.assertRaisesRegex(AuditReadError, "line 2"):
                    load_audit_records(self.path)

    def test_missing_truncated_and_invalid_utf8(self):
        with self.assertRaises(AuditReadError):
            load_audit_records(self.path)
        for content in (json.dumps(entry()).encode(), b"\xff\n"):
            self.path.write_bytes(content)
            with self.assertRaises(AuditReadError):
                load_audit_records(self.path)


class AuditMatchTests(unittest.TestCase):
    def test_matches_by_id_preserving_result_order(self):
        results = (result(), result("r2"))
        records = tuple(FileReadAuditEntry(**entry(i)) for i in ("r2", "r1"))
        matched = match_audit_records(results, records)
        self.assertEqual(tuple(item.result for item in matched), results)
        self.assertEqual([item.audit.request_id for item in matched], ["r1", "r2"])

    def test_missing_extra_and_duplicate_ids(self):
        one = FileReadAuditEntry(**entry())
        two = FileReadAuditEntry(**entry("r2"))
        for results, records in (
            ((result(),), ()), ((), (one,)), ((result(),), (one, two)),
            ((result(), result()), (one,)), ((result(),), (one, one)),
        ):
            with self.subTest(results=results, records=records):
                with self.assertRaises(AuditMatchError):
                    match_audit_records(results, records)

    def test_disagreeing_fields(self):
        for field, value in (
            ("original_path", "other"), ("policy_decision", "allowed"),
            ("reason", "other"),
        ):
            with self.subTest(field=field):
                record = FileReadAuditEntry(**entry(**{field: value}))
                with self.assertRaises(AuditMatchError):
                    match_audit_records((result(),), (record,))


if __name__ == "__main__":
    unittest.main()
