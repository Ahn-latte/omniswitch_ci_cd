import re

from switchtest.domain.device import DeviceDefinition
from switchtest.domain.enums import TransportType
from switchtest.drivers.aos import (
    SUPER_USER_PASSWORD_PROMPT,
    AOSSwitchDriver,
    _extract_firmware,
    _extract_model,
)
from switchtest.exceptions import CommandExecutionError
from switchtest.exceptions import ConnectionError as SwitchConnectionError
from switchtest.infrastructure.console.client import SerialConsoleTransport
from switchtest.infrastructure.ssh.client import SSHTransport


SHOW_SYSTEM_OUTPUT = """ACSW01-> show system

  Description:  Alcatel-Lucent Enterprise OS6860E-P24 8.9.221.R03 GA, October 12, 2023.,
  Object ID:    1.3.6.1.4.1.6486.801.1.1.2.1.11.1.6,
  Up Time:      12 days 4 hours 24 minutes and 21 seconds,
  Contact:      jerry.poh@al-enterprise.com,
  Name:         ACSW01,
  Location:     ALE Demo Lab,
  Services:     78,
  Date & Time:  SUN MAR 29 2026 15:43:07 (ZP8)
"""


def test_extract_model_from_show_system() -> None:
    assert _extract_model(SHOW_SYSTEM_OUTPUT) == "OS6860E-P24"


def test_extract_firmware_from_show_system() -> None:
    assert _extract_firmware(SHOW_SYSTEM_OUTPUT) == "8.9.221.R03 GA"


def _device(**overrides) -> DeviceDefinition:
    defaults = dict(
        name="dev",
        host="192.168.1.1",
        username="secureadmin",
        password="not-a-real-password",
        platform="aos",
        expected_prompt="->",
    )
    defaults.update(overrides)
    return DeviceDefinition(**defaults)


class _RecordingSwitch:
    """Answers `show` with content and configuration commands with silence,
    which is how AOS actually behaves on success."""

    def __init__(self, show_output: str = "Name: OS6900", empty_first_read: bool = False) -> None:
        self.sent: list[str] = []
        self._show_output = show_output
        self._empty_first_read = empty_first_read

    def send_command(self, command: str, timeout: int = 30) -> str:
        self.sent.append(command)
        if not command.startswith("show"):
            return ""
        if self._empty_first_read and len(self.sent) == 1:
            return ""
        return self._show_output


def _driver_with(transport) -> AOSSwitchDriver:
    driver = AOSSwitchDriver(_device())
    driver.transport = transport
    return driver


class _RecordingSuShell:
    """Records each send_interactive batch as the list of inputs it sent, so a
    test can assert the whole dialogue (su, commands, exit) and its order."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.batches: list[list[str]] = []
        self.patterns: list[list[str]] = []
        self.auth_password = "not-a-real-password"
        self._fail_on = fail_on

    def send_interactive(self, interactions, timeout: int = 30) -> str:
        inputs = [channel_input for channel_input, _prompt, _hidden in interactions]
        self.batches.append(inputs)
        self.patterns.append([prompt for _input, prompt, _hidden in interactions])
        if self._fail_on is not None and self._fail_on in inputs:
            raise RuntimeError(f"timed out waiting after {self._fail_on!r}")
        return (
            "-rw------- 1 root root 1675 Jan 1 00:05 /flash/system/ssh_host_rsa_key\n"
            "MEDORA #-> \n"
        )


class _RecordingPasswordDialogue:
    """Records the inputs and the prompt each one waits for, so a test can
    assert the last entry is the one that returns to the CLI.

    Answers each send_interactive call from `responses` in turn: the driver
    sends the command on its own first and only continues if that first
    answer asked for a password, so the opening response decides whether
    there is a dialogue at all."""

    def __init__(self, responses: list[str] | None = None) -> None:
        self.interactions: list[tuple[str, str, bool]] = []
        self.calls = 0
        self.auth_password = "not-a-real-password"
        self._responses = responses or ["Enter super-user password:", "set successfully.\n"]

    def send_interactive(self, interactions, timeout: int = 30) -> str:
        self.interactions.extend(interactions)
        response = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return response


def test_super_user_password_is_entered_twice_and_ends_at_the_cli_prompt() -> None:
    transport = _RecordingPasswordDialogue()

    _driver_with(transport).set_super_user_password("12#qweASD")

    inputs = [channel_input for channel_input, _prompt, _hidden in transport.interactions]
    assert inputs == ["super-user-password set", "12#qweASD", "12#qweASD"]
    # The confirmation entry waits for another password prompt; only the last
    # one waits for the CLI prompt. Getting this backwards would either strand
    # the session at a prompt or send the password to the CLI as a command.
    assert transport.interactions[1][1] == SUPER_USER_PASSWORD_PROMPT
    assert "->" in transport.interactions[2][1]
    # Both password entries are marked hidden so they are not echoed.
    assert transport.interactions[1][2] is True
    assert transport.interactions[2][2] is True


def test_super_user_password_honors_a_single_entry_dialogue() -> None:
    transport = _RecordingPasswordDialogue()

    _driver_with(transport).set_super_user_password("12#qweASD", entries=1)

    inputs = [channel_input for channel_input, _prompt, _hidden in transport.interactions]
    assert inputs == ["super-user-password set", "12#qweASD"]
    assert "->" in transport.interactions[1][1]


def test_a_rejection_after_the_entries_raises() -> None:
    """A refusal arrives as output text, not as a transport error, so it has
    to be read out of the output."""
    transport = _RecordingPasswordDialogue(
        responses=["Enter old super-user password:", "ERROR: Incorrect super-user password"]
    )

    try:
        _driver_with(transport).reset_super_user_password("wrong")
    except CommandExecutionError as exc:
        assert "Incorrect" in str(exc)
    else:
        raise AssertionError("a rejected password should have raised")


def test_reset_asks_for_the_old_password_once() -> None:
    transport = _RecordingPasswordDialogue(
        responses=["Enter old super-user password:", "reset successfully.\n"]
    )

    _driver_with(transport).reset_super_user_password("12#qweASD")

    inputs = [channel_input for channel_input, _prompt, _hidden in transport.interactions]
    assert inputs == ["super-user-password reset", "12#qweASD"]
    assert "->" in transport.interactions[1][1]


def test_a_command_that_never_asks_is_refused_without_typing_the_password() -> None:
    """`reset` with no password set plausibly answers with a one-line refusal
    and goes straight back to the CLI. Sending the password regardless would
    type it at the CLI -- into swlog -- and waiting for a prompt that never
    comes would be a timeout that `ignore_errors` does not forgive."""
    transport = _RecordingPasswordDialogue(responses=["ERROR: No super-user password is set\n"])

    try:
        _driver_with(transport).reset_super_user_password("12#qweASD")
    except CommandExecutionError as exc:
        assert "did not ask for a password" in str(exc)
    else:
        raise AssertionError("a command that never prompted should have raised")

    assert transport.calls == 1
    assert "12#qweASD" not in [channel_input for channel_input, _p, _h in transport.interactions]


def test_the_opening_step_accepts_either_a_password_prompt_or_the_cli_prompt() -> None:
    """The first step can't assume which one comes back -- but the CLI half
    must still be the one the maintenance shell's prompt cannot satisfy."""
    transport = _RecordingPasswordDialogue()

    _driver_with(transport).set_super_user_password("12#qweASD")

    opening_pattern = transport.interactions[0][1]
    assert re.match(opening_pattern, "Enter super-user password:")
    assert re.match(opening_pattern, "Reenter super-user password: ")
    assert re.match(opening_pattern, "ACSW01-> ")
    assert not re.match(opening_pattern, "MEDORA #-> ")


def test_su_shell_runs_the_commands_and_always_exits_back_to_the_cli() -> None:
    transport = _RecordingSuShell()

    output = _driver_with(transport).run_in_su_shell(["ls -l /flash/system/ssh*"])

    assert "ssh_host_rsa_key" in output
    # No su password configured, so no "Password:" step -- su goes straight to
    # the shell prompt, then the command, then exit as its own batch.
    assert transport.batches == [["su", "ls -l /flash/system/ssh*"], ["exit"]]


def test_the_maintenance_shell_prompt_is_not_accepted_as_the_cli_prompt() -> None:
    """`MEDORA #-> ` ends in "->", so the ordinary CLI prompt pattern matches
    it ("MEDORA #" is a legal `.*[^-]`). If `exit` were verified with that
    pattern, a session still sitting in the shell would look like it had
    returned to the CLI -- and every later command would quietly run in the
    Linux shell instead."""
    driver = _driver_with(_RecordingSuShell())
    shell_prompt_line = "MEDORA #-> "

    assert re.match(driver._cli_prompt_pattern(), shell_prompt_line)
    assert not re.match(driver._cli_prompt_pattern_outside_su(), shell_prompt_line)
    # The real CLI prompt, with and without a hostname, still matches.
    assert re.match(driver._cli_prompt_pattern_outside_su(), "ACSW01-> ")
    assert re.match(driver._cli_prompt_pattern_outside_su(), "-> ")
    # And the swlog arrows the original pattern exists to reject still are.
    assert not re.match(driver._cli_prompt_pattern_outside_su(), "Process --->")


def test_su_shell_verifies_the_exit_with_the_pattern_the_shell_cannot_satisfy() -> None:
    transport = _RecordingSuShell()

    driver = _driver_with(transport)
    driver.run_in_su_shell(["ls -l /flash/system/ssh*"])

    assert transport.patterns[-1] == [driver._cli_prompt_pattern_outside_su()]


def test_su_shell_waits_for_the_device_prompt_tail_allowing_any_alias() -> None:
    """The alias in front of `#->` differs per device, so the pattern has to
    allow any prefix rather than having the alias configured anywhere."""
    transport = _RecordingSuShell()

    _driver_with(transport).run_in_su_shell(["ls /flash/system"])

    shell_pattern = transport.patterns[0][-1]
    assert re.match(shell_pattern, "MEDORA #-> ")
    assert re.match(shell_pattern, "SOMEOTHERBOX #-> ")


def test_su_shell_sends_the_password_when_one_is_configured() -> None:
    transport = _RecordingSuShell()

    _driver_with(transport).run_in_su_shell(["ls /flash/system"], su_password="su-secret")

    assert transport.batches[0] == ["su", "su-secret", "ls /flash/system"]


def test_su_shell_exits_even_when_a_command_fails() -> None:
    """A session left sitting at a shell prompt breaks every later step of the
    run, which then fails for reasons that look unrelated to this testcase."""
    transport = _RecordingSuShell(fail_on="ls -l /nope")

    try:
        _driver_with(transport).run_in_su_shell(["ls -l /nope"])
    except RuntimeError:
        pass
    else:
        raise AssertionError("the failing command should have propagated")

    assert transport.batches[-1] == ["exit"]


def test_su_shell_keeps_the_original_error_when_the_exit_also_fails() -> None:
    """The exit is best-effort on the failure path: letting it raise would
    replace the error that actually says what went wrong."""
    transport = _RecordingSuShell(fail_on="exit")

    try:
        _driver_with(transport).run_in_su_shell(["ls -l /flash/system/ssh*"])
    except Exception as exc:
        # The command batch succeeded here, so this is the exit's own failure
        # surfacing -- reported as a stranded session, not swallowed.
        assert "stranded" in str(exc)
    else:
        raise AssertionError("a failed exit should have been reported")


def test_a_silent_configuration_command_is_not_sent_twice() -> None:
    """Several testcases assert on a configuration command's output, and a
    command that succeeds says nothing. Retrying on empty would run it again --
    and a second `user X password P` is refused as a reuse of the password the
    first one just set, turning a success into a failure (TC-IA-124)."""
    switch = _RecordingSwitch()

    output = _driver_with(switch).run_show("user admin1 password Qet135!#%")

    assert switch.sent == ["user admin1 password Qet135!#%"]
    assert output == ""


def test_an_empty_first_read_of_a_show_is_still_retried() -> None:
    # The serial console does return nothing on a first read; that is what the
    # retry is for, and it has to keep working.
    switch = _RecordingSwitch(empty_first_read=True)

    output = _driver_with(switch).run_show("show system")

    assert switch.sent == ["show system", "show system"]
    assert output == "Name: OS6900"


def test_driver_uses_ssh_transport_by_default(monkeypatch) -> None:
    monkeypatch.setenv("SWITCH_TEST_PASSWORD", "secret")
    transport = AOSSwitchDriver(_device())._build_transport()
    assert isinstance(transport, SSHTransport)


def test_driver_uses_serial_transport_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("SWITCH_TEST_PASSWORD", "secret")
    device = _device(transport=TransportType.SERIAL, serial_port="COM9", serial_baudrate=115200)

    transport = AOSSwitchDriver(device)._build_transport()

    assert isinstance(transport, SerialConsoleTransport)
    assert transport.serial_port == "COM9"
    assert transport.baudrate == 115200
    assert transport.prompt == "->"


def test_failed_login_attempts_stay_on_ssh_for_serial_devices(monkeypatch) -> None:
    # The IP ban under test is triggered by network logins; a console attempt
    # would never register against this machine's IP.
    monkeypatch.setenv("SWITCH_TEST_PASSWORD", "secret")
    device = _device(transport=TransportType.SERIAL, serial_port="COM9")
    built: list[SSHTransport] = []

    class RecordingTransport(SSHTransport):
        def connect(self) -> None:
            built.append(self)
            raise SwitchConnectionError("rejected")

        def close(self) -> None:
            return None

    monkeypatch.setattr("switchtest.drivers.aos.SSHTransport", RecordingTransport)

    assert AOSSwitchDriver(device).attempt_login("admin1", "wrong") is False
    assert built[0].host == "192.168.1.1"
    assert built[0].port == 22
