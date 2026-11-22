"""Offline CLI configuration checks; never read the user's environment file."""
import importlib.util
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr
from io import StringIO

AVAILABLE = all(importlib.util.find_spec(name) is not None
                for name in ("dotenv", "langchain_openai"))
if AVAILABLE:
    from attack_runner.run_agent import load_environment, parse_inputs


@unittest.skipUnless(AVAILABLE, "Install the agents extra")
class RunAgentConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {}, clear=True))

    def test_existing_values_win_and_missing_values_are_added(self):
        path = self.directory / "settings.env"
        path.write_text('TEST_KEY=file-value\nTEST_NEW=new-value\n', encoding="utf-8")
        os.environ["TEST_KEY"] = "existing-value"
        load_environment(path)
        self.assertEqual(os.environ["TEST_KEY"], "existing-value")
        self.assertEqual(os.environ["TEST_NEW"], "new-value")

    def test_existing_empty_value_is_preserved(self):
        path = self.directory / "settings.env"
        path.write_text('TEST_KEY=file-value\n', encoding="utf-8")
        os.environ["TEST_KEY"] = ""
        load_environment(path)
        self.assertEqual(os.environ["TEST_KEY"], "")

    def test_interpolation_is_disabled(self):
        path = self.directory / "settings.env"
        path.write_text('TEST_KEY=${OTHER_KEY}\n', encoding="utf-8")
        os.environ["OTHER_KEY"] = "expanded-value"
        load_environment(path)
        self.assertEqual(os.environ["TEST_KEY"], "${OTHER_KEY}")

    def test_no_file_does_not_search_or_load(self):
        with patch("attack_runner.run_agent.load_dotenv") as loader:
            load_environment(None)
        loader.assert_not_called()
        self.assertEqual(dict(os.environ), {})

    def test_missing_file_or_directory_raises(self):
        for path in (self.directory / "missing.env", self.directory):
            with self.subTest(path=path), self.assertRaises(OSError):
                load_environment(path)
        self.assertEqual(dict(os.environ), {})

    def test_permission_error_propagates(self):
        with patch.object(Path, "open", side_effect=PermissionError("test denial")):
            with self.assertRaises(PermissionError):
                load_environment(self.directory / "settings.env")

    def test_invalid_utf8_raises(self):
        path = self.directory / "settings.env"
        path.write_bytes(b'\xff')
        with self.assertRaises(UnicodeDecodeError):
            load_environment(path)
        self.assertEqual(dict(os.environ), {})

    def test_parse_defaults_without_loading_file(self):
        path = self.directory / "missing.env"
        config = parse_inputs([
            "--task", "Read public/readme.txt", "--model", "test-model",
            "--workspace", str(self.directory), "--env-file", str(path),
        ])
        self.assertEqual(config.env_file, path)
        self.assertEqual(config.model.max_retries, 0)
        self.assertEqual(config.model.max_tokens, 256)
        self.assertEqual(config.loop.max_steps, 3)
        self.assertEqual(config.filesystem.max_read_bytes, 1024)
        self.assertEqual(config.filesystem.authorized_roots, ())

    def test_repeated_roots_and_invalid_limits(self):
        args = ["--task", "task", "--model", "test-model", "--workspace", str(self.directory)]
        config = parse_inputs(args + ["--allowed-root", "public", "--allowed-root", "docs"])
        self.assertEqual(config.filesystem.authorized_roots, ("public", "docs"))
        for flags in (["--max-steps", "0"], ["--request-timeout", "nan"],
                      ["--max-read-bytes", "-1"], ["--task", " "]):
            with self.subTest(flags=flags), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    parse_inputs(args + flags)
                self.assertEqual(caught.exception.code, 2)


@unittest.skipUnless(AVAILABLE, "Install the agents extra")
class RunAgentMainTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import AsyncMock, sentinel
        from agents.models import AgentFinalAnswer
        from attack_runner.execution.agent_loop import AgentLoopResult
        from attack_runner.execution.agent_run import AgentRunResult
        from attack_runner.run_agent import main
        self.main = main
        self.args = ["--task", "test task", "--model", "test-model", "--workspace", "/fixture"]
        self.platform = self.enterContext(patch("attack_runner.run_agent.sys.platform", "linux"))
        self.load = self.enterContext(patch("attack_runner.run_agent.load_environment"))
        self.model = self.enterContext(patch("attack_runner.run_agent.create_chat_model", return_value=sentinel.model))
        self.adapter = self.enterContext(patch("attack_runner.run_agent.LangChainAgentAdapter", return_value=sentinel.agent))
        self.audit = self.enterContext(patch("attack_runner.run_agent.create_audit_path", return_value=Path("/audit/events.jsonl")))
        self.loop_result = AgentLoopResult(AgentFinalAnswer("PRIVATE-FINAL-TEXT"), (), 2)
        self.execute = self.enterContext(patch(
            "attack_runner.run_agent.execute_agent_run",
            AsyncMock(return_value=AgentRunResult(self.loop_result, ())),
        ))

    def invoke(self, args=None):
        from contextlib import redirect_stdout
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.main(self.args if args is None else args)
        return code, out.getvalue(), err.getvalue()

    def test_success_outputs_metadata_and_passes_configuration(self):
        import json
        code, out, err = self.invoke()
        record = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["steps"], 2)
        self.assertEqual(record["completed_tool_calls"], 0)
        self.assertNotIn("PRIVATE-FINAL-TEXT", out + err)
        self.assertNotIn("verdict", record)
        self.assertIn("/audit/events.jsonl", err)
        self.execute.assert_awaited_once()
        kwargs = self.execute.await_args.kwargs
        self.assertEqual(kwargs["task"], "test task")
        self.assertEqual(kwargs["loop"].max_steps, 3)
        self.assertEqual(kwargs["filesystem"].max_read_bytes, 1024)
        self.assertEqual(kwargs["audit_path"], Path("/audit/events.jsonl"))

    def test_unsupported_platform_stops_before_setup(self):
        with patch("attack_runner.run_agent.sys.platform", "darwin"):
            code, out, err = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.load.assert_not_called()
        self.model.assert_not_called()
        self.execute.assert_not_awaited()

    def test_invalid_arguments_stop_before_setup(self):
        with self.assertRaises(SystemExit) as caught:
            self.invoke(self.args + ["--max-steps", "0"])
        self.assertEqual(caught.exception.code, 2)
        self.load.assert_not_called()
        self.execute.assert_not_awaited()

    def test_each_setup_failure_is_sanitized_and_stops_execution(self):
        for component in (self.load, self.model, self.adapter, self.audit):
            with self.subTest(component=component):
                component.side_effect = ValueError("PRIVATE-ERROR-TEXT")
                try:
                    code, out, err = self.invoke()
                finally:
                    component.side_effect = None
                self.assertEqual(code, 3)
                self.assertEqual(out, "")
                self.assertIn("ValueError", err)
                self.assertNotIn("PRIVATE-ERROR-TEXT", err)
        self.execute.assert_not_awaited()

    def test_aborted_phases_report_available_steps_and_record_count(self):
        import json
        from attack_runner.execution.agent_loop import AgentLoopAbortedError
        from attack_runner.execution.agent_run import AgentRunAbortedError
        loop_error = AgentLoopAbortedError(reason="step_limit", phase="limit", history=(), steps=3)
        variants = [
            (AgentRunAbortedError(phase="connect", records=()), None, None),
            (AgentRunAbortedError(phase="loop", records=(), loop_error=loop_error), 3, "step_limit"),
            (AgentRunAbortedError(phase="close", records=(), loop_result=self.loop_result), 2, None),
            (AgentRunAbortedError(phase="close", records=(), loop_error=loop_error), 3, "step_limit"),
        ]
        for error, steps, reason in variants:
            with self.subTest(phase=error.phase, reason=reason):
                self.execute.side_effect = error
                code, out, err = self.invoke()
                record = json.loads(out)
                self.assertEqual(code, 3)
                self.assertEqual(record["status"], "aborted")
                self.assertEqual(record["phase"], error.phase)
                self.assertEqual(record["steps"], steps)
                self.assertEqual(record["reason"], reason)
                self.assertEqual(record["completed_tool_calls"], len(error.records))
                self.assertNotIn("PRIVATE-FINAL-TEXT", out + err)

    def test_unexpected_execution_error_is_sanitized(self):
        self.execute.side_effect = RuntimeError("PRIVATE-ERROR-TEXT")
        code, out, err = self.invoke()
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertIn("RuntimeError", err)
        self.assertNotIn("PRIVATE-ERROR-TEXT", err)

    def test_keyboard_interrupt_returns_130(self):
        self.execute.side_effect = KeyboardInterrupt()
        code, out, err = self.invoke()
        self.assertEqual(code, 130)
        self.assertEqual(out, "")
        self.assertIn("interrupted", err)
