from dataclasses import dataclass
import logging
import platform
import socket

from switchtest.exceptions import ConnectionError

try:
    from scrapli.driver import GenericDriver
    SCRAPLI_IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover
    GenericDriver = None
    SCRAPLI_IMPORT_ERROR = exc


@dataclass
class SSHTransport:
    host: str
    port: int
    auth_username: str
    auth_password: str
    auth_secondary: str | None = None
    timeout_socket: int = 15
    timeout_ops: int = 30
    auth_strict_key: bool = False

    def __post_init__(self) -> None:
        self._connection = None

    def connect(self) -> None:
        if GenericDriver is None:
            detail = f": {SCRAPLI_IMPORT_ERROR}" if SCRAPLI_IMPORT_ERROR else ""
            raise ConnectionError(f"scrapli could not be imported{detail}")
        _configure_paramiko_logging()
        transport_name = _select_transport()
        self._connection = GenericDriver(
            host=self.host,
            port=self.port,
            auth_username=self.auth_username,
            auth_password=self.auth_password,
            auth_strict_key=self.auth_strict_key,
            timeout_socket=self.timeout_socket,
            timeout_ops=self.timeout_ops,
            transport=transport_name,
        )
        try:
            self._connection.open()
        except Exception as exc:
            raise ConnectionError(
                f"Failed to connect to {self.host}:{self.port} using transport '{transport_name}': {exc}"
            ) from exc

    def send_command(self, command: str, timeout: int = 30) -> str:
        if self._connection is None:
            raise ConnectionError("SSH connection is not open")
        response = self._connection.send_command(command, timeout_ops=timeout)
        return str(response.result)

    def send_commands(self, commands: list[str], timeout: int = 30) -> list[str]:
        return [self.send_command(command, timeout=timeout) for command in commands]

    def send_interactive(
        self,
        interactions: list[tuple[str, str, bool]],
        timeout: int = 30,
    ) -> str:
        """Drive a command that expects intermediate prompts (e.g. ``Password:``).

        Each interaction is ``(channel_input, expected_prompt, hidden_input)``;
        set ``hidden_input`` to ``True`` for secrets so they are not echoed.
        """
        if self._connection is None:
            raise ConnectionError("SSH connection is not open")
        response = self._connection.send_interactive(interactions, timeout_ops=timeout)
        return str(response.result)

    def close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            except OSError as exc:
                if not _is_ignorable_windows_close_error(exc):
                    raise
            except Exception as exc:
                if not _is_ignorable_windows_close_error(exc):
                    raise
            self._connection = None


def _select_transport() -> str:
    if platform.system().lower() == "windows":
        return "paramiko"
    return "system"


def _is_ignorable_windows_close_error(exc: BaseException) -> bool:
    if platform.system().lower() != "windows":
        return False
    message = str(exc).lower()
    if "10038" in message:
        return True
    if isinstance(exc, OSError) and getattr(exc, "winerror", None) == 10038:
        return True
    if isinstance(exc, socket.error) and getattr(exc, "errno", None) == 10038:
        return True
    return False


def _configure_paramiko_logging() -> None:
    if platform.system().lower() != "windows":
        return
    logger = logging.getLogger("paramiko.transport")
    if any(isinstance(existing, _ParamikoSocketNoiseFilter) for existing in logger.filters):
        return
    logger.addFilter(_ParamikoSocketNoiseFilter())


class _ParamikoSocketNoiseFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage().lower()
        if "socket exception:" in message and "10038" in message:
            return False
        return True
