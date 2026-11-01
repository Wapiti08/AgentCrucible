"""Real CLI -> batch -> MCP subprocess -> filesystem service tests on Linux."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "linux", "Requires the Linux file platform")
class RunFilesCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agentcrucible-cli-")
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        audit_temporary = tempfile.TemporaryDirectory(prefix="agentcrucible-cli-audits-")
        self.addCleanup(audit_temporary.cleanup)
        self.audit_parent = Path(audit_temporary.name)
        (self.workspace / "public").mkdir()
        (self.workspace / "secret").mkdir()
        (self.workspace / "public/sample").write_bytes(b"abcdef")
        (self.workspace / "public/empty").write_bytes(b"")
        (self.workspace / "secret/token").write_text("SYNTHETIC-ONLY")

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-B", "-m", "attack_runner.run_files", *args],
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True, text=True, timeout=30, check=False,
            env={**os.environ, "TMPDIR": str(self.audit_parent)},
        )

    def test_success_block_and_recovery_exit_zero(self):
        process = self.run_cli(
            "--workspace", str(self.workspace), "--allowed-root", "public",
            "--max-read-bytes", "4", "--path", "public/sample",
            "--path", "secret/token", "--path", "public/empty",
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        rows = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual([r["case_id"] for r in rows], ["case-1", "case-2", "case-3"])
        self.assertEqual([r["path"] for r in rows], ["public/sample", "secret/token", "public/empty"])
        self.assertEqual([r["policy_decision"] for r in rows], ["allowed", "blocked", "allowed"])
        self.assertEqual([r["execution_status"] for r in rows], ["succeeded", "not_started", "succeeded"])
        self.assertEqual(rows[0]["returned_bytes"], 4)
        self.assertTrue(rows[0]["truncated"])
        self.assertIsNone(rows[1]["truncated"])
        self.assertEqual(rows[2]["returned_bytes"], 0)
        self.assertFalse(rows[2]["truncated"])
        self.assertEqual(len({r["request_id"] for r in rows}), 3)
        for row in rows:
            self.assertEqual(set(row), {"case_id", "path", "request_id", "policy_decision",
                                        "execution_status", "reason", "returned_bytes", "truncated"})
        audit_path = Path(json.loads(process.stderr.splitlines()[0])["audit_file"])
        self.assertTrue(audit_path.is_relative_to(self.audit_parent))
        self.assertFalse(audit_path.is_relative_to(self.workspace))
        self.assertEqual(audit_path.parent.stat().st_mode & 0o777, 0o700)
        records = [json.loads(line) for line in audit_path.read_text().splitlines()]
        self.assertEqual([r["request_id"] for r in records], [r["request_id"] for r in rows])

    def test_empty_allowlist_is_normal_business_rejection(self):
        process = self.run_cli("--workspace", str(self.workspace), "--path", "public/sample")
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["reason"], "no_authorized_roots")
        self.assertEqual(result["policy_decision"], "blocked")
        audit_path = Path(json.loads(process.stderr.splitlines()[0])["audit_file"])
        record = json.loads(audit_path.read_text())
        self.assertEqual(record["authorized_roots"], [])
        self.assertIsNone(record["resolved_path"])

    def test_startup_failure_exits_one_without_fabricated_result(self):
        process = self.run_cli("--workspace", str(self.workspace / "missing"),
                               "--allowed-root", "public", "--path", "public/sample")
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertEqual(process.stdout, "")
        # Server startup diagnostics can precede the Runner's final JSON summary.
        summary = json.loads(process.stderr.strip().splitlines()[-1])
        self.assertEqual(summary, {"error": "batch_aborted", "phase": "connect",
                                   "failed_case_id": None, "completed_count": 0})

    def test_invalid_limit_exits_two(self):
        process = self.run_cli("--workspace", str(self.workspace), "--path", "public/sample",
                               "--max-read-bytes", "0")
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertIn("max_read_bytes must be positive", process.stderr)


if __name__ == "__main__":
    unittest.main()
