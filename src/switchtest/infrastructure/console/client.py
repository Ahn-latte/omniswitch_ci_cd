"""Serial (RS-232 / USB-serial) console transport.

Mirrors the public surface of
:class:`switchtest.infrastructure.ssh.client.SSHTransport` -- ``connect``,
``send_command``, ``send_commands``, ``send_interactive``, ``close``, plus the
``auth_password``/``auth_secondary`` attributes the AOS driver reads -- so the
driver can hold its session over either transport without special-casing every
call site.

The difference that matters for testing is out-of-band access: a serial console
is not reachable over IP, so it keeps working while the switch is refusing
network logins from this machine (IP ban) or while the account under test is
locked. Unlike SSH there is no protocol-level authentication, so this transport
drives the console's own ``login:``/``Password:`` dialogue itself.
"""

from dataclasses import dataclass
import re
import time

from switchtest.exceptions import AuthenticationError, ConnectionError

try:
    import serial as pyserial
    from serial import SerialException

    SERIAL_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - exercised only without pyserial
    pyserial = None
    SerialException = Exception
    SERIAL_IMPORT_ERROR = exc


READ_POLL_SECONDS = 0.2
LOGIN_PROMPT_PATTERN = re.compile(r"(?i)(login|username)\s*:\s*$")
PASSWORD_PROMPT_PATTERN = re.compile(r"(?i)password\s*:\s*$")
LOGIN_FAILURE_PATTERN = re.compile(
    r"(?i)(login incorrect|authentication failed|access denied|permission denied)"
)
# The console pages long output (swlog is the reason this matters). Answering
# the pager in the read loop keeps this transport independent of which AOS
# release spells the "disable paging" command which way.
PAGER_PATTERN = re.compile(r"(?i)(--\s*more\s*--|\(\s*more\s*\)|more\s*\?|press any key)")
# `exit` with unsaved running-config changes -- which every testcase that
# touches configuration leaves behind -- makes AOS ask for confirmation before
# it lets go of the session. See _logout() for why the answer is always `y`.
CONFIRM_PATTERN = re.compile(r"(?i)[(\[]\s*y(?:es)?\s*[/|]\s*n(?:o)?\s*[)\]]\s*[:?]?\s*$")


@dataclass
class SerialConsoleTransport:
    serial_port: str
    auth_username: str
    auth_password: str
    baudrate: int = 9600
    auth_secondary: str | None = None
    prompt: str = "->"
    timeout_socket: int = 15
    timeout_ops: int = 30

    def __post_init__(self) -> None:
        self._connection = None
        # `(?:.*[^-])?` rather than `.*`: readers match this against the buffer
        # as it fills, and `$` matches at end-of-string too, so a chunk boundary
        # landing right after "... CPU Status --->" would otherwise look like a
        # finished prompt line and cut the read short. Excluding a preceding
        # "-" keeps "->" and "OS6900->" matching while "--->" does not.
        self._prompt_pattern = re.compile(
            rf"(?m)^(?:.*[^-])?{re.escape(self.prompt)}\s*$",
        )

    # -- lifecycle ---------------------------------------------------------

    def connect(self) -> None:
        if pyserial is None:
            detail = f": {SERIAL_IMPORT_ERROR}" if SERIAL_IMPORT_ERROR else ""
            raise ConnectionError(f"pyserial could not be imported{detail}")
        try:
            self._connection = pyserial.Serial(
                port=self.serial_port,
                baudrate=self.baudrate,
                bytesize=pyserial.EIGHTBITS,
                parity=pyserial.PARITY_NONE,
                stopbits=pyserial.STOPBITS_ONE,
                timeout=READ_POLL_SECONDS,
                write_timeout=self.timeout_socket,
            )
        except (SerialException, OSError, ValueError) as exc:
            raise ConnectionError(
                f"Failed to open serial console {self.serial_port} at {self.baudrate} baud: {exc}"
            ) from exc
        try:
            self._login()
        except Exception:
            self._close_port()
            raise

    def close(self) -> None:
        if self._connection is None:
            return
        try:
            # Log out so the console is left at its login prompt: an
            # authenticated console left open would count against the device's
            # one-session-per-account limit for the next run.
            self._logout(timeout=self.timeout_socket)
        except Exception:
            pass
        self._close_port()

    # -- commands ----------------------------------------------------------

    def send_command(self, command: str, timeout: int = 30) -> str:
        connection = self._require_connection()
        connection.reset_input_buffer()
        self._write(command)
        output = self._read_until(
            _matcher(self._prompt_pattern),
            timeout=timeout,
            expecting=f"prompt '{self.prompt}' after '{command}'",
        )
        return _strip_echo_and_prompt(output, command, self._prompt_pattern)

    def send_commands(self, commands: list[str], timeout: int = 30) -> list[str]:
        return [self.send_command(command, timeout=timeout) for command in commands]

    def send_interactive(
        self,
        interactions: list[tuple[str, str, bool]],
        timeout: int = 30,
    ) -> str:
        """Drive a command that expects intermediate prompts (e.g. ``Password:``).

        Each interaction is ``(channel_input, expected_prompt, hidden_input)``.
        ``expected_prompt`` follows scrapli's convention -- treated as a
        multiline regex when it starts with ``^`` and ends with ``$``, otherwise
        as a literal substring -- so callers written against ``SSHTransport``
        behave identically here.
        """
        self._require_connection()
        collected: list[str] = []
        first_command = interactions[0][0] if interactions else ""
        for channel_input, expected_prompt, _hidden in interactions:
            self._write(channel_input)
            collected.append(
                self._read_until(
                    _expected_matcher(expected_prompt),
                    timeout=timeout,
                    expecting=f"'{expected_prompt}'",
                )
            )
        return _strip_echo_and_prompt("".join(collected), first_command, self._prompt_pattern)

    # -- login -------------------------------------------------------------

    def _login(self) -> None:
        connection = self._require_connection()
        connection.reset_input_buffer()
        # A bare CR makes the console redraw whatever prompt it is sitting at.
        self._write("")
        seen = self._read_until(
            _any_matcher(LOGIN_PROMPT_PATTERN, PASSWORD_PROMPT_PATTERN, self._prompt_pattern),
            timeout=self.timeout_socket,
            expecting="console login prompt",
        )
        if self._at_prompt(seen):
            # A previous run left the console logged in. Log out and back in so
            # the session is definitely the configured account.
            seen = self._logout(timeout=self.timeout_socket, stale=True)
        if LOGIN_PROMPT_PATTERN.search(_tail(seen)):
            self._write(self.auth_username)
            self._read_until(
                _matcher(PASSWORD_PROMPT_PATTERN),
                timeout=self.timeout_socket,
                expecting="password prompt",
            )
        self._write(self.auth_password)
        result = self._read_until(
            _any_matcher(self._prompt_pattern, LOGIN_PROMPT_PATTERN, LOGIN_FAILURE_PATTERN),
            timeout=self.timeout_socket,
            expecting=f"prompt '{self.prompt}' after login",
        )
        if not self._at_prompt(result):
            raise AuthenticationError(
                f"Console login as '{self.auth_username}' on {self.serial_port} was rejected"
            )

    def _logout(self, timeout: int, stale: bool = False) -> str:
        """Send `exit` and read back to the login prompt.

        With unsaved running-config changes pending -- the normal state at the
        end of a testcase that configured anything -- AOS doesn't just log out,
        it asks whether to leave them unsaved ("...(Y/N)"). Left unanswered the
        session never returns to the login prompt and this times out.

        The answer is always `y`, i.e. leave without saving: testcases restore
        whatever they changed in their own cleanup, so the running config is
        already back where it belongs and there is nothing worth writing to
        flash. `write memory` here would do the opposite of a favour -- it
        would persist whatever state a half-finished run happened to leave.
        """
        self._write("exit")
        expecting = "login prompt after logging out"
        if stale:
            expecting = "console login prompt after logging out a stale session"
        deadline = time.monotonic() + timeout
        buffer = ""
        while time.monotonic() < deadline:
            chunk = self._read_chunk()
            if not chunk:
                continue
            buffer = self._answer_pager(buffer + chunk)
            tail = _tail(buffer)
            if CONFIRM_PATTERN.search(tail):
                self._write("y")
                buffer = buffer[: len(buffer) - len(tail)]
                continue
            if LOGIN_PROMPT_PATTERN.search(_tail(buffer)):
                return buffer
        raise ConnectionError(
            f"Timed out after {timeout}s waiting for {expecting} on serial console "
            f"{self.serial_port}. Last output: {_tail(buffer, lines=3)!r}"
        )

    def _at_prompt(self, text: str) -> bool:
        tail = _tail(text)
        if LOGIN_PROMPT_PATTERN.search(tail) or PASSWORD_PROMPT_PATTERN.search(tail):
            return False
        return self._prompt_pattern.search(text) is not None

    # -- plumbing ----------------------------------------------------------

    def _require_connection(self):
        if self._connection is None:
            raise ConnectionError("Serial console is not open")
        return self._connection

    def _write(self, text: str) -> None:
        self._write_raw(f"{text}\r")

    def _write_raw(self, payload: str) -> None:
        connection = self._require_connection()
        try:
            connection.write(payload.encode())
            connection.flush()
        except (SerialException, OSError) as exc:
            raise ConnectionError(f"Serial console write to {self.serial_port} failed: {exc}") from exc

    def _read_chunk(self) -> str:
        connection = self._require_connection()
        try:
            chunk = connection.read(connection.in_waiting or 1)
        except (SerialException, OSError) as exc:
            raise ConnectionError(
                f"Serial console read from {self.serial_port} failed: {exc}"
            ) from exc
        return _decode(chunk)

    def _read_until(self, matcher, timeout: int, expecting: str) -> str:
        deadline = time.monotonic() + timeout
        buffer = ""
        while time.monotonic() < deadline:
            chunk = self._read_chunk()
            if not chunk:
                continue
            buffer = self._answer_pager(buffer + chunk)
            if matcher(buffer):
                return buffer
        raise ConnectionError(
            f"Timed out after {timeout}s waiting for {expecting} on serial console "
            f"{self.serial_port}. Last output: {_tail(buffer, lines=3)!r}"
        )

    def _answer_pager(self, buffer: str) -> str:
        """Page through paginated output, dropping the pager prompt itself."""
        tail = _tail(buffer)
        if not PAGER_PATTERN.search(tail):
            return buffer
        # A bare space asks for the next *page*; CR would advance one line at a
        # time and make long output (swlog) crawl.
        self._write_raw(" ")
        return buffer[: len(buffer) - len(tail)]

    def _close_port(self) -> None:
        connection, self._connection = self._connection, None
        if connection is None:
            return
        try:
            connection.close()
        except (SerialException, OSError):
            pass


def _decode(chunk: bytes) -> str:
    return chunk.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def _tail(text: str, lines: int = 1) -> str:
    return "\n".join(text.split("\n")[-lines:])


def _matcher(pattern: re.Pattern[str]):
    return lambda text: pattern.search(text) is not None


def _any_matcher(*patterns: re.Pattern[str]):
    return lambda text: any(pattern.search(text) for pattern in patterns)


def _expected_matcher(expected: str):
    """Match scrapli's rule: anchored patterns are regexes, everything else is
    a literal substring."""
    if expected.startswith("^") and expected.endswith("$"):
        pattern = re.compile(expected, re.MULTILINE)
        return lambda text: pattern.search(text) is not None
    return lambda text: expected in text


def _strip_echo_and_prompt(text: str, command: str, prompt_pattern: re.Pattern[str]) -> str:
    """Drop the console's echo of the command and the trailing prompt line, so
    output looks like what scrapli returns over SSH."""
    lines = text.split("\n")
    normalized = command.strip()
    if normalized and lines and lines[0].strip().endswith(normalized):
        lines = lines[1:]
    while lines and (not lines[-1].strip() or prompt_pattern.search(lines[-1])):
        lines.pop()
    return "\n".join(lines).strip("\n")
