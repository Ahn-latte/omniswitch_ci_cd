from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator
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
    # scrapli caps a single read from the transport at `timeout_transport`
    # independently of `timeout_ops`. Left at scrapli's 30s default it silently
    # becomes the real ceiling for any slow command, which is what a per-call
    # `timeout=` is supposed to control -- see `_operation_timeout`.
    timeout_transport: int = 30
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
            timeout_transport=self.timeout_transport,
            transport=transport_name,
        )
        try:
            self._connection.open()
        except Exception as exc:
            raise ConnectionError(
                f"Failed to connect to {self.host}:{self.port} using transport '{transport_name}': {exc}"
            ) from exc

    @contextmanager
    def _operation_timeout(self, timeout: int) -> Iterator[None]:
        """Let a per-call ``timeout`` govern the transport read as well.

        ``timeout_ops`` bounds the whole operation, but scrapli bounds each
        individual read by ``timeout_transport`` (30s by default), so asking
        for a 90s command still dies at 30 -- with "timed out reading from
        transport" rather than anything that points here. Raise the transport
        ceiling for the duration of the call, never lower it, and always put
        the connection's own value back.
        """
        connection = self._connection
        previous = connection.timeout_transport
        if timeout > previous:
            connection.timeout_transport = timeout
        try:
            yield
        finally:
            connection.timeout_transport = previous

    def send_command(self, command: str, timeout: int = 30) -> str:
        if self._connection is None:
            raise ConnectionError("SSH connection is not open")
        with self._operation_timeout(timeout):
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
        with self._operation_timeout(timeout):
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
    logger = logging.getLogger("paramiko.transport")
    if any(isinstance(existing, _ParamikoSocketNoiseFilter) for existing in logger.filters):
        return
    logger.addFilter(_ParamikoSocketNoiseFilter())


class _ParamikoSocketNoiseFilter(logging.Filter):
    """Drop paramiko's own tracebacks for conditions this project handles.

    These are logged from paramiko's transport thread, so they print a full
    traceback even though the exception is caught and dealt with here. That
    reads like a crash in the middle of a run that is in fact fine.

    Nothing is silenced that the caller is not told about some other way:
    a banner read that fails is reported by the retry loop ("switch not
    reachable yet ..."), and a failure that survives every retry still raises
    ConnectionError with the host and transport in the message.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage().lower()
        if platform.system().lower() == "windows" and "socket exception:" in message and "10038" in message:
            return False
        # What a still-banned switch looks like: it accepts the TCP connection
        # and then closes it without sending a banner.
        if "error reading ssh protocol banner" in message:
            return False
        return True
