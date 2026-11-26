from pathlib import Path
import re
import time

from switchtest.domain.device import DeviceDefinition
from switchtest.domain.enums import TransportType
from switchtest.drivers.base import BaseSwitchDriver
from switchtest.exceptions import BaselineRestoreError, CommandExecutionError
from switchtest.exceptions import ConnectionError as SwitchConnectionError
from switchtest.infrastructure.console.client import SerialConsoleTransport
from switchtest.infrastructure.secrets import resolve_optional_secret, resolve_secret
from switchtest.infrastructure.ssh.client import SSHTransport
from switchtest.infrastructure.ssh.prompt import PASSWORD_PROMPT_PATTERN, is_password_prompt

DriverTransport = SSHTransport | SerialConsoleTransport

# Matched by shape rather than exact wording: "Enter new password:", "Retype
# new password:", "Confirm super user password:" all differ by firmware but
# all end the same way. Anchored because scrapli only treats a pattern as a
# regex when it starts with ^ and ends with $.
SUPER_USER_PASSWORD_PROMPT = r"^.*[Pp]assword.*:\s*$"


class AOSSwitchDriver(BaseSwitchDriver):
    def __init__(self, device: DeviceDefinition) -> None:
        self.device = device
        self.transport: DriverTransport | None = None

    def connect(self) -> None:
        self.transport = self._build_transport()
        self.transport.connect()

    def _build_transport(self) -> DriverTransport:
        password = resolve_secret(
            self.device.password, self.device.password_env, f"device '{self.device.name}'"
        )
        secondary = resolve_optional_secret(
            self.device.enable_password, self.device.enable_password_env
        )
        if self.device.transport == TransportType.SERIAL:
            return SerialConsoleTransport(
                serial_port=self.device.serial_port or "",
                auth_username=self.device.username,
                auth_password=password,
                baudrate=self.device.serial_baudrate,
                auth_secondary=secondary,
                prompt=self.device.expected_prompt or "->",
                timeout_socket=self.device.connection_timeout,
                timeout_ops=self.device.command_timeout,
            )
        return SSHTransport(
            host=self.device.host,
            port=self.device.port,
            auth_username=self.device.username,
            auth_password=password,
            auth_secondary=secondary,
            timeout_socket=self.device.connection_timeout,
            timeout_ops=self.device.command_timeout,
            auth_strict_key=self.device.strict_host_key,
        )

    def disconnect(self) -> None:
        if self.transport is not None:
            self.transport.close()

    def enter_enable_mode(self) -> None:
        if not self.device.enable_password and not self.device.enable_password_env:
            return
        transport = self._transport()
        result = transport.send_interactive(
            [
                ("enable", "Password:", False),
                (transport.auth_secondary or "", "->", True),
            ],
            timeout=self.device.command_timeout,
        )
        if is_password_prompt(result):
            raise CommandExecutionError(
                "Enable authentication failed: device is still requesting a password"
            )

    def enter_config_mode(self) -> None:
        self._transport().send_command("configure terminal", timeout=self.device.command_timeout)

    def exit_config_mode(self) -> None:
        self._transport().send_command("end", timeout=self.device.command_timeout)

    def run_show(self, command: str, timeout: int = 30, reauth: bool = False) -> str:
        if reauth:
            return self._run_show_with_reauth(command, timeout)
        output = self._transport().send_command(command, timeout=timeout)
        cleaned = _clean_show_output(output, command)
        if cleaned or not _is_repeatable(command):
            return cleaned
        # An empty first read happens on the console, so a read is worth asking
        # for twice. Only a read: several testcases assert on the output of a
        # configuration command, and one that succeeds says nothing at all --
        # re-sending it would apply it twice. `user X password P` is the case
        # that bites, because the second attempt is refused as a reuse of the
        # password the first attempt just set, turning a success into a failure.
        time.sleep(0.2)
        retry_output = self._transport().send_command(command, timeout=timeout)
        return _clean_show_output(retry_output, command)

    def _cli_prompt_pattern(self) -> str:
        """The anchored pattern that matches only the trailing CLI prompt line.

        scrapli only treats a pattern as a (multiline) regex when it starts
        with ^ and ends with $; anything else is matched as a bare substring.
        A bare "->" would match the "--->" arrows that pepper swlog output
        (e.g. "Process ---> Ok"), cutting the read off at the first such line
        and dropping everything after it. Anchoring makes it match only the
        trailing CLI prompt line.

        Anchoring alone is not enough, because readers match against the
        buffer as it accumulates and `$` also matches at end-of-string: a
        chunk boundary landing right after "... CPU Status --->" (before
        " Ok" arrives) makes "^.*->$" match a half-read line and truncate the
        output. That is a constant hazard on the 115200 serial console. So
        also require the character before the prompt not to be part of an
        arrow -- "->" and "OS6900->" still match, "--->" no longer does.
        """
        prompt = self.device.expected_prompt or "->"
        return f"^(?:.*[^-])?{re.escape(prompt)}\\s*$"

    def _cli_prompt_pattern_outside_su(self) -> str:
        """`_cli_prompt_pattern`, narrowed so the maintenance shell's own
        prompt cannot satisfy it.

        The su shell prompts with "<alias> #-> " -- which ends in "->" and so
        matches the ordinary CLI pattern too ("MEDORA #" is a legal match for
        that pattern's `.*[^-]`). That makes "did `exit` get us back to the
        CLI?" unanswerable with the ordinary pattern: it is already true
        inside the shell. Worse, a session accidentally left in the shell
        would then keep answering every later send_command as if it were the
        CLI, quietly running those commands in the Linux shell instead.

        Excluding `#` from the prompt line separates the two: "ACSW01-> " and
        "-> " still match, "MEDORA #-> " no longer does. AOS system names
        don't contain `#`, and an swlog line that does is one fewer false
        prompt match -- so narrowing costs nothing here.
        """
        prompt = self.device.expected_prompt or "->"
        return f"^(?:[^#]*[^-#])?{re.escape(prompt)}\\s*$"

    def _run_show_with_reauth(self, command: str, timeout: int) -> str:
        transport = self._transport()
        prompt_pattern = self._cli_prompt_pattern()
        output = transport.send_interactive(
            [
                (command, "Password:", False),
                (transport.auth_password, prompt_pattern, True),
            ],
            timeout=timeout,
        )
        return _clean_show_output(output, command)

    def apply_config(
        self, commands: list[str], timeout: int = 30, ignore_errors: bool = False
    ) -> list[str]:
        outputs = self._transport().send_commands(commands, timeout=timeout)
        if ignore_errors:
            return outputs
        for output in outputs:
            if any(marker in output.lower() for marker in ["invalid input", "incomplete command", "error"]):
                raise CommandExecutionError(f"Device rejected configuration command: {output}")
        return outputs

    def set_super_user_password(self, password: str, entries: int = 2, timeout: int = 30) -> str:
        """Drive `super-user-password set` -- the dialogue that gives `su` a
        password to ask for. As the device prints it:

            -> super-user-password set
            Enter super-user password:   *********
            Reenter super-user password: *********
            The super-user password was set successfully.

        `entries` is how many times it asks (2 above). A parameter rather
        than a constant because getting it wrong does not fail cleanly: one
        entry too few leaves the session sitting at a password prompt, and one
        too many sends the password to the CLI as a command, which puts it in
        swlog.
        """
        return self._super_user_password_dialogue(
            "super-user-password set", password, entries, timeout
        )

    def reset_super_user_password(self, old_password: str, timeout: int = 30) -> str:
        """Drive `super-user-password reset`, which removes the password
        altogether (not "changes it") and asks for the current one first:

            -> super-user-password reset
            Enter old super-user password:   *********
            The super-user password was reset successfully.
        """
        return self._super_user_password_dialogue(
            "super-user-password reset", old_password, 1, timeout
        )

    def _super_user_password_dialogue(
        self, command: str, password: str, entries: int, timeout: int
    ) -> str:
        """Send `command`, and only then decide whether there is a dialogue.

        The first prompt cannot be assumed. `reset` with no password set, or
        `set` with one already there, very plausibly answers with a one-line
        refusal and goes straight back to the CLI -- never asking for
        anything. A fixed script would then wait for a password prompt that
        never comes (a timeout, which `ignore_errors` deliberately does not
        forgive), and a script that didn't wait would type the password at
        the CLI, where it lands in swlog. So the command goes out on its own,
        expecting either a password prompt or the CLI prompt, and the
        password is sent only if what came back actually asked for it.

        The CLI half of that is the `#`-excluding pattern so it is the same
        one used everywhere a "back at the CLI" judgement matters.
        """
        transport = self._transport()
        prompt = self.device.expected_prompt or "->"
        either = rf"^(?:.*[Pp]assword.*:|(?:[^#]*[^-#])?{re.escape(prompt)})\s*$"
        opening = transport.send_interactive([(command, either, False)], timeout=timeout)
        if not _ends_at_password_prompt(opening):
            # Answered without asking -- a refusal, or at least not the
            # dialogue we came for. Raised as a rejection (which a step's
            # `ignore_errors` may forgive), and crucially before the password
            # has been typed anywhere.
            raise CommandExecutionError(
                f"'{command}' did not ask for a password: {opening.strip() or '(no output)'}"
            )
        interactions: list[tuple[str, str, bool]] = []
        # Every entry but the last is answered by another password prompt; the
        # last one is what returns the session to the CLI.
        for index in range(entries):
            last = index == entries - 1
            expected = self._cli_prompt_pattern_outside_su() if last else SUPER_USER_PASSWORD_PROMPT
            interactions.append((password, expected, True))
        output = opening + transport.send_interactive(interactions, timeout=timeout)
        if any(
            marker in output.lower()
            for marker in ["error", "invalid", "incorrect", "do not match", "does not match"]
        ):
            raise CommandExecutionError(f"Device rejected '{command}': {output.strip()}")
        return output

    def run_in_su_shell(
        self,
        commands: list[str],
        su_password: str | None = None,
        shell_prompt: str = "#->",
        timeout: int = 30,
    ) -> str:
        """Run `commands` in the `su` shell, then come back to the CLI.

        AOS keeps /flash/system out of reach of both the ordinary CLI's file
        commands and SFTP, so the su shell is the only place the files in it
        (the generated SSH host keys, for one) can be observed at all.

        The dialogue, as the device actually prints it:

            -> su
            Password:
            Entering maintenance shell. Type 'exit' when you are done.
            MEDORA #->

        So `shell_prompt` defaults to the `#->` tail rather than to the whole
        prompt: the part in front of it is a per-device alias ("MEDORA"
        here), and the pattern built from it allows any prefix, which keeps
        this working across devices without configuring the alias anywhere.

        The shell is always left again, including when a command in the
        middle fails: a session stranded at a shell prompt breaks every
        later step of the run, which then looks like an unrelated failure in
        whatever testcase happens to come next -- and because that prompt
        ends in "->" it would not even look stranded, it would look like a
        CLI that has started answering very strangely.
        """
        transport = self._transport()
        shell_pattern = f"^.*{re.escape(shell_prompt)}\\s*$"
        interactions: list[tuple[str, str, bool]] = []
        if su_password:
            interactions.append(("su", "Password:", False))
            interactions.append((su_password, shell_pattern, True))
        else:
            interactions.append(("su", shell_pattern, False))
        interactions.extend((command, shell_pattern, False) for command in commands)
        try:
            output = transport.send_interactive(interactions, timeout=timeout)
        except Exception:
            # Best effort only, and deliberately not allowed to raise: an exit
            # that also fails must not replace the original error, which says
            # far more about what actually went wrong.
            try:
                self._leave_su_shell(timeout)
            except Exception:
                pass
            raise
        self._leave_su_shell(timeout)
        return output

    def _leave_su_shell(self, timeout: int) -> None:
        try:
            # The `#`-excluding pattern, not the ordinary one: the shell's own
            # prompt satisfies the ordinary one, so this check would pass
            # without having left the shell at all.
            self._transport().send_interactive(
                [("exit", self._cli_prompt_pattern_outside_su(), False)], timeout=timeout
            )
        except Exception as exc:
            raise CommandExecutionError(
                "Could not get back to the CLI prompt after the su shell -- the session is "
                f"stranded in the shell, so later steps will fail too: {exc}"
            ) from exc

    def restore_baseline(self, source: str | None = None) -> None:
        if not source:
            return
        path = Path(source)
        if not path.exists():
            raise BaselineRestoreError(f"Baseline file not found: {source}")
        commands = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("!")
        ]
        if commands:
            self.apply_config(commands, timeout=max(self.device.command_timeout, 60))

    def get_metadata(self) -> dict[str, str | None]:
        version_output = self.run_show("show system", timeout=self.device.command_timeout)
        return {
            "firmware_version": _extract_firmware(version_output),
            "device_model": _extract_model(version_output),
        }

    def attempt_login(self, username: str, password: str, timeout: int = 15) -> bool:
        # Always SSH, even when the driver's own session is a serial console:
        # the point of the lockout/IP-ban testcases is that the failed attempts
        # arrive over the network from this machine's IP, which is exactly what
        # the switch counts and then bans. Console attempts would not.
        transport = SSHTransport(
            host=self.device.host,
            port=self.device.port,
            auth_username=username,
            auth_password=password,
            timeout_socket=timeout,
            timeout_ops=timeout,
            auth_strict_key=self.device.strict_host_key,
        )
        try:
            transport.connect()
        except SwitchConnectionError:
            # connect() assigns the underlying driver before opening it, so a
            # rejected login still leaves an object holding a socket -- close
            # it rather than leaking one per failed attempt.
            transport.close()
            return False
        transport.close()
        return True

    def _transport(self) -> DriverTransport:
        if self.transport is None:
            raise CommandExecutionError(
                f"{self.device.transport.value} transport is not connected"
            )
        return self.transport


def _ends_at_password_prompt(text: str) -> bool:
    """Whether the last thing the device printed is a request for a password.

    Judged on the last non-empty line, so it holds whether or not the
    transport stripped a trailing CLI prompt from the output it returned."""
    for line in reversed(text.splitlines()):
        if line.strip():
            return re.search(r"[Pp]assword.*:\s*$", line) is not None
    return False


def _is_repeatable(command: str) -> bool:
    """Whether running the command a second time is guaranteed to be harmless.

    Only reads qualify. AOS has no way to say "this was a query", so this goes
    by the verb, which is what every read in these testcases starts with.
    """
    return command.strip().lower().startswith("show")


def _extract_first_line(text: str) -> str | None:
    lines = _meaningful_lines(text)
    return lines[0] if lines else None


def _extract_model(text: str) -> str | None:
    description = _extract_description(text)
    if description:
        match = re.search(r"\b(OS[0-9A-Z-]+)\b", description)
        if match:
            return match.group(1)
    for line in text.splitlines():
        stripped = line.strip()
        if "model" in stripped.lower():
            return stripped
    return _extract_first_line(text)


def _extract_firmware(text: str) -> str | None:
    description = _extract_description(text)
    if description:
        match = re.search(r"\b\d+(?:\.\d+)+(?:\.[A-Z0-9]+)?(?:\s+[A-Z]+)?\b", description)
        if match:
            return match.group(0).strip()
    return _extract_first_line(text)


def _extract_description(text: str) -> str | None:
    for stripped in _meaningful_lines(text):
        if stripped.lower().startswith("description:"):
            return stripped.split(":", 1)[1].strip(" ,.")
    return None


def _meaningful_lines(text: str) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "-> show " in stripped.lower():
            continue
        if stripped.endswith(("->", "#", ">")) and " " not in stripped:
            continue
        lines.append(stripped)
    return lines


def _clean_show_output(text: str, command: str) -> str:
    lines: list[str] = []
    normalized_command = command.strip().lower()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if PASSWORD_PROMPT_PATTERN.search(stripped):
            continue
        lowered = stripped.lower()
        if lowered == normalized_command:
            continue
        if normalized_command and lowered.endswith(normalized_command) and "->" in lowered:
            continue
        if stripped.endswith(("->", "#", ">")) and " " not in stripped:
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip()
