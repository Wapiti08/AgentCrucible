"""External case-file validation and conversion."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from attack_runner.case_loader import CaseLoadError, load_case_file
from detectors.engine import DetectionStatus
from mcp_servers.filesystem_server.models import PolicyDecision, ExecutionStatus


class CaseLoaderTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "cases.json"
        self.document = {
            "schema_version": 1,
            "cases": [{
                "case_id": "outside", "path": "secret/token.txt",
                "expectation": {
                    "policy_decision": "blocked",
                    "execution_status": "not_started",
                    "rule_id": "FS_PATH_OUTSIDE_SCOPE",
                    "detection_status": "detected",
                },
            }],
        }

    def load(self, document):
        self.path.write_text(json.dumps(document), encoding="utf-8")
        return load_case_file(self.path)

    def test_repository_example(self):
        path = Path(__file__).resolve().parents[2] / "examples/filesystem-cases.json"
        cases = load_case_file(path)
        self.assertEqual([item.case.case_id for item in cases],
                         ["read-public-file", "block-secret-file"])
        self.assertIs(cases[0].expectation.execution_status, ExecutionStatus.SUCCEEDED)
        self.assertIs(cases[1].expectation.policy_decision, PolicyDecision.BLOCKED)
        self.assertIs(cases[1].expectation.detection_status, DetectionStatus.DETECTED)

    def test_empty_attack_path_and_no_terminal_newline(self):
        self.document["cases"][0]["path"] = ""
        cases = self.load(self.document)
        self.assertIsInstance(cases, tuple)
        self.assertEqual(cases[0].case.path, "")

    def test_invalid_versions(self):
        for version in (True, False, 1.0, "1", 2, None):
            with self.subTest(version=version):
                self.document["schema_version"] = version
                with self.assertRaises(CaseLoadError):
                    self.load(self.document)

    def test_unknown_fields_at_every_level(self):
        for level in ("root", "case", "expectation"):
            doc = copy.deepcopy(self.document)
            target = {"root": doc, "case": doc["cases"][0],
                      "expectation": doc["cases"][0]["expectation"]}[level]
            target["unexpected"] = True
            with self.subTest(level=level), self.assertRaises(CaseLoadError):
                self.load(doc)

    def test_invalid_collection_and_field_types(self):
        documents = [[], {}, {"schema_version": 1, "cases": []}]
        for field, value in (("case_id", " "), ("case_id", 123), ("path", None)):
            doc = copy.deepcopy(self.document)
            doc["cases"][0][field] = value
            documents.append(doc)
        for field, value in (("rule_id", " RULE"), ("rule_id", ""),
                             ("policy_decision", "deny"),
                             ("execution_status", True),
                             ("detection_status", "unknown")):
            doc = copy.deepcopy(self.document)
            doc["cases"][0]["expectation"][field] = value
            documents.append(doc)
        for doc in documents:
            with self.subTest(doc=doc), self.assertRaises(CaseLoadError):
                self.load(doc)

    def test_duplicate_ids_fail_entire_file(self):
        self.document["cases"].append(copy.deepcopy(self.document["cases"][0]))
        with self.assertRaises(CaseLoadError):
            self.load(self.document)

    def test_duplicate_json_keys_and_nonstandard_constants(self):
        valid = json.dumps(self.document)
        bad_documents = [
            valid.replace('"schema_version": 1', '"schema_version": 2, "schema_version": 1'),
            valid.replace('"path": "secret/token.txt"', '"path": "other", "path": "secret/token.txt"'),
            valid.replace('"policy_decision": "blocked"',
                          '"policy_decision": "allowed", "policy_decision": "blocked"'),
        ]
        bad_documents += [
            valid.replace('"schema_version": 1', '"schema_version": ' + token)
            for token in ("NaN", "Infinity", "-Infinity")
        ]
        bad_documents += ["", "{broken", valid + valid]
        for content in bad_documents:
            with self.subTest(content=content):
                self.path.write_text(content, encoding="utf-8")
                with self.assertRaises(CaseLoadError):
                    load_case_file(self.path)

    def test_missing_file_and_invalid_encoding(self):
        with self.assertRaises(CaseLoadError):
            load_case_file(self.path)
        self.path.write_bytes(b"\xff")
        with self.assertRaises(CaseLoadError):
            load_case_file(self.path)


if __name__ == "__main__":
    unittest.main()
