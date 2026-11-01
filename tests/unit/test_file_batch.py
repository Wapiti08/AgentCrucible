"""Portable checks for batch ordering, isolation of failures and cancellation."""

import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from hashlib import sha256
import unittest
from unittest.mock import AsyncMock, Mock, call, patch

from attack_runner.batch import (
    BatchAbortedError, FileReadCase, run_file_batch, validate_cases,
)
from attack_runner.mcp_models import FileReadResponse
from mcp_servers.filesystem_server.models import FileServiceConfig


def response(request_id, blocked=False):
    return FileReadResponse(
        request_id=request_id,
        policy_decision="blocked" if blocked else "allowed",
        execution_status="not_started" if blocked else "succeeded",
        reason="outside_authorized_roots" if blocked else "ok",
        content_base64=None if blocked else "",
        returned_bytes=0,
        truncated=None if blocked else False,
        content_sha256=None if blocked else sha256(b"").hexdigest(),
    )


class ValidateCasesTests(unittest.TestCase):
    def test_snapshot_preserves_attack_inputs_and_repeated_paths(self):
        cases = [FileReadCase("one", ""), FileReadCase("two", "../secret"),
                 FileReadCase("three", "../secret")]
        snapshot = validate_cases(cases)
        self.assertEqual(snapshot, tuple(cases))
        cases.clear()
        self.assertEqual(len(snapshot), 3)

    def test_invalid_batches(self):
        for cases in ([], "abc", [{}], [FileReadCase(" ", "a")],
                      [FileReadCase("x", None)],
                      [FileReadCase("x", "a"), FileReadCase("x", "b")]):
            with self.subTest(cases=cases):
                with self.assertRaises((TypeError, ValueError)):
                    validate_cases(cases)


class FileBatchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config = FileServiceConfig("/fixture", ("public",), 4)
        self.audit_path = Path("/audit/events.jsonl")
        self.cases = (FileReadCase("one", "public/a"),
                      FileReadCase("two", "secret/a"),
                      FileReadCase("three", "public/b"))
        self.session = object()
        self.events = []
        self.connect_error = None
        self.close_error = None

        @asynccontextmanager
        async def connect(config, *, audit_path):
            self.assertEqual(audit_path, self.audit_path)
            self.events.append("enter")
            if self.connect_error is not None:
                raise self.connect_error
            try:
                yield self.session
            finally:
                self.events.append("exit")
                if self.close_error is not None:
                    raise self.close_error

        self.connect = Mock(side_effect=connect)
        self.responses = [response("r1"), response("r2", True), response("r3")]
        self.read = AsyncMock(side_effect=self.responses)
        self.enterContext(patch("attack_runner.batch.connect_filesystem_server", self.connect))
        self.enterContext(patch("attack_runner.batch.read_file", self.read))

    async def test_reuses_connection_and_preserves_order_after_block(self):
        results = await run_file_batch(self.cases, self.config, audit_path=self.audit_path)
        self.connect.assert_called_once_with(self.config, audit_path=self.audit_path)
        self.assertEqual(self.events, ["enter", "exit"])
        self.assertIsInstance(results, tuple)
        self.assertEqual([r.case_id for r in results], [c.case_id for c in self.cases])
        self.assertEqual([r.path for r in results], [c.path for c in self.cases])
        self.assertEqual([r.response for r in results], self.responses)
        self.assertEqual(self.read.await_args_list, [
            call(self.session, case.path, max_read_bytes=4) for case in self.cases
        ])

    async def test_duplicate_ids_prevent_connection(self):
        with self.assertRaises(ValueError):
            await run_file_batch((self.cases[0], self.cases[0]), self.config, audit_path=self.audit_path)
        self.connect.assert_not_called()
        self.read.assert_not_awaited()

    async def test_connect_failure_has_no_failed_case(self):
        self.connect_error = OSError("synthetic connect failure")
        with self.assertRaises(BatchAbortedError) as caught:
            await run_file_batch(self.cases, self.config, audit_path=self.audit_path)
        error = caught.exception
        self.assertEqual(error.phase, "connect")
        self.assertIsNone(error.failed_case)
        self.assertEqual(error.completed_results, ())
        self.assertIs(error.__cause__, self.connect_error)
        self.read.assert_not_awaited()

    async def test_call_failure_retains_completed_results_without_retry(self):
        for failure in (TimeoutError("synthetic timeout"), ValueError("invalid response")):
            with self.subTest(failure=type(failure).__name__):
                self.events.clear()
                self.read.reset_mock()
                self.read.side_effect = [self.responses[0], failure]
                with self.assertRaises(BatchAbortedError) as caught:
                    await run_file_batch(self.cases, self.config, audit_path=self.audit_path)
                error = caught.exception
                self.assertEqual(error.phase, "call")
                self.assertEqual(error.failed_case, self.cases[1])
                self.assertEqual(len(error.completed_results), 1)
                self.assertEqual(error.completed_results[0].response, self.responses[0])
                self.assertIs(error.__cause__, failure)
                self.assertEqual(self.read.await_count, 2)
                self.assertEqual(self.events, ["enter", "exit"])

    async def test_close_failure_retains_all_results(self):
        self.close_error = OSError("synthetic cleanup failure")
        with self.assertRaises(BatchAbortedError) as caught:
            await run_file_batch(self.cases, self.config, audit_path=self.audit_path)
        error = caught.exception
        self.assertEqual(error.phase, "close")
        self.assertIsNone(error.failed_case)
        self.assertEqual(len(error.completed_results), 3)
        self.assertIs(error.__cause__, self.close_error)

    async def test_cancellation_propagates_and_exits_connection(self):
        cancellation = asyncio.CancelledError()
        self.read.side_effect = [self.responses[0], cancellation]
        with self.assertRaises(asyncio.CancelledError) as caught:
            await run_file_batch(self.cases, self.config, audit_path=self.audit_path)
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(self.events, ["enter", "exit"])
        self.assertEqual(self.read.await_count, 2)


if __name__ == "__main__":
    unittest.main()
