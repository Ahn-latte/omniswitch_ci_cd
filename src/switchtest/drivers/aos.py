from pathlib import Path
import re
import time

from switchtest.domain.device import DeviceDefinition
from switchtest.drivers.base import BaseSwitchDriver
from switchtest.exceptions import BaselineRestoreError, CommandExecutionError
from switchtest.exceptions import ConnectionError as SwitchConnectionError
from switchtest.infrastructure.secrets import get_optional_secret, get_required_secret
from switchtest.infrastructure.ssh.client import SSHTransport
from switchtest.infrastructure.ssh.prompt import PASSWORD_PROMPT_PATTERN, is_password_prompt


class AOSSwitchDriver(BaseSwitchDriver):
    def __init__(self, device: DeviceDefinition) -> None:
        self.device = device
        self.transport: SSHTransport | None = None

    def connect(self) -> None:
        self.transport = SSHTransport(
            host=self.device.host,
            port=self.device.port,
            auth_username=self.device.username,
            auth_password=get_required_secret(self.device.password_env),
            auth_secondary=get_optional_secret(self.device.enable_password_env),
            timeout_socket=self.device.connection_timeout,
            timeout_ops=self.device.command_timeout,
            auth_strict_key=self.device.strict_host_key,
        )
        self.transport.connect()

    def disconnect(self) -> None:
        if self.transport is not None:
            self.transport.close()

    def enter_enable_mode(self) -> None:
        if not self.device.enable_password_env:
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
        if cleaned:
            return cleaned
        time.sleep(0.2)
        retry_output = self._transport().send_command(command, timeout=timeout)
        return _clean_show_output(retry_output, command)

    def _run_show_with_reauth(self, command: str, timeout: int) -> str:
        transport = self._transport()
        prompt = self.device.expected_prompt or "->"
        # Anchor the completion prompt to a whole line. scrapli only treats a
        # pattern as a (multiline) regex when it starts with ^ and ends with $;
        # anything else is matched as a bare substring. A bare "->" would match
        # the "--->" arrows that pepper swlog output (e.g. "Process ---> Ok"),
        # cutting the read off at the first such line and dropping everything
        # after it. Anchoring makes it match only the trailing CLI prompt line.
        prompt_pattern = f"^.*{re.escape(prompt)}\\s*$"
        output = transport.send_interactive(
            [
                (command, "Password:", False),
                (transport.auth_password, prompt_pattern, True),
            ],
            timeout=timeout,
        )
        return _clean_show_output(output, command)

    def apply_config(self, commands: list[str], timeout: int = 30) -> list[str]:
        outputs = self._transport().send_commands(commands, timeout=timeout)
        for output in outputs:
            if any(marker in output.lower() for marker in ["invalid input", "incomplete command", "error"]):
                raise CommandExecutionError(f"Device rejected configuration command: {output}")
        return outputs

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
            return False
        transport.close()
        return True

    def _transport(self) -> SSHTransport:
        if self.transport is None:
            raise CommandExecutionError("SSH transport is not connected")
        return self.transport


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
