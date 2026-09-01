"""Regression tests for the shell-injection fix in client.bot.Bot._run_cmd.

_run_cmd must invoke subprocess.run with an argument list and without
shell=True, so that values such as a CA common name or a P12 password can
never be interpreted as shell syntax.
"""

from __future__ import annotations

from unittest import mock

import pytest

from client.bot import Bot


class _FakeLogger:
    def write(self, message, level=None):
        pass


@pytest.fixture()
def bot() -> Bot:
    # Bypass Bot.__init__ (it talks to the RA over the network); we only
    # need self._logger for _run_cmd/_output to work.
    instance = Bot.__new__(Bot)
    instance._logger = _FakeLogger()
    return instance


class TestRunCmdShellSafety:
    def test_run_cmd_does_not_use_shell(self, bot):
        with mock.patch("client.bot.subprocess.run") as run:
            bot._run_cmd(["certutil", "-A", "-n", "uPKI-CA"])

        assert run.call_args.kwargs.get("shell") is not True

    def test_run_cmd_passes_args_as_list_not_a_joined_string(self, bot):
        with mock.patch("client.bot.subprocess.run") as run:
            bot._run_cmd(["pk12util", "-i", "/tmp/node.p12", "-W", "s3cr3t"])

        called_cmd = run.call_args.args[0]
        assert called_cmd == ["pk12util", "-i", "/tmp/node.p12", "-W", "s3cr3t"]

    def test_shell_metacharacters_in_argument_are_not_interpreted(self, bot):
        """A malicious/unexpected value must be treated as a literal argument."""
        malicious_name = "Evil CA; rm -rf /tmp/pwned"

        with mock.patch("client.bot.subprocess.run") as run:
            bot._run_cmd(["certutil", "-A", "-n", malicious_name])

        called_cmd = run.call_args.args[0]
        # The whole malicious string must remain a single, literal argument.
        assert malicious_name in called_cmd
        assert run.call_args.kwargs.get("shell") is not True

    def test_run_cmd_suppresses_stdout_and_stderr(self, bot):
        with mock.patch("client.bot.subprocess.run") as run:
            bot._run_cmd(["certtool", "i", "/tmp/node.pem"])

        assert run.call_args.kwargs.get("stdout") is not None
        assert run.call_args.kwargs.get("stderr") is not None
