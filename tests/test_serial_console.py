import pytest

from switchtest.exceptions import AuthenticationError, ConnectionError
from switchtest.infrastructure.console import client as console_client
from switchtest.infrastructure.console.client import SerialConsoleTransport


class FakeSerial:
    """Stand-in for pyserial's Serial: replays scripted device output.

    ``script`` maps the text written by the transport to what the console
    answers. ``\\r`` is what the transport sends as a line terminator, so keys
    are the bare inputs (``""`` for the initial bare CR, ``" "`` for the space
    that answers a pager). A list value replays one response per write.
    """

    def __init__(self, script: dict[str, str | list[str]], **_kwargs) -> None:
        self.script = script
        self.writes: list[str] = []
        self._pending = ""
        self.closed = False

    @property
    def in_waiting(self) -> int:
        return len(self._pending)

    def write(self, payload: bytes) -> int:
        text = payload.decode().rstrip("\r")
        self.writes.append(text)
        response = self.script.get(text, "")
        if isinstance(response, list):
            response = response.pop(0) if response else ""
        self._pending += response
        return len(payload)

    def flush(self) -> None:
        return None

    def read(self, size: int = 1) -> bytes:
        chunk, self._pending = self._pending[:size], self._pending[size:]
        return chunk.encode()

    def reset_input_buffer(self) -> None:
        self._pending = ""

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_serial(monkeypatch):
    """Install a FakeSerial built from the per-test script."""

    holder: dict[str, FakeSerial] = {}

    def install(script: dict[str, str]) -> FakeSerial:
        fake = FakeSerial(script)
        holder["fake"] = fake
        monkeypatch.setattr(console_client.pyserial, "Serial", lambda **kwargs: fake)
        return fake

    return install


def _transport(**overrides) -> SerialConsoleTransport:
    defaults = dict(
        serial_port="COM9",
        auth_username="secureadmin",
        auth_password="secret",
        timeout_socket=2,
        timeout_ops=2,
    )
    defaults.update(overrides)
    return SerialConsoleTransport(**defaults)


LOGIN_SCRIPT = {
    "": "\r\nlogin: ",
    "secureadmin": "\r\nPassword: ",
    "secret": "\r\nWelcome to the Alcatel-Lucent Enterprise CLI\r\nACSW01-> ",
}


def test_login_drives_console_dialogue(fake_serial) -> None:
    fake = fake_serial(LOGIN_SCRIPT)
    transport = _transport()

    transport.connect()

    assert fake.writes == ["", "secureadmin", "secret"]


def test_login_rejected_raises(fake_serial) -> None:
    fake_serial(
        {
            "": "\r\nlogin: ",
            "secureadmin": "\r\nPassword: ",
            "secret": "\r\nLogin incorrect\r\nlogin: ",
        }
    )
    transport = _transport()

    with pytest.raises(AuthenticationError):
        transport.connect()


def test_login_logs_out_a_stale_session_first(fake_serial) -> None:
    fake = fake_serial(
        {
            # Console already authenticated from a previous run.
            "": "\r\nACSW01-> ",
            "exit": "\r\nlogin: ",
            "secureadmin": "\r\nPassword: ",
            "secret": "\r\nACSW01-> ",
        }
    )
    transport = _transport()

    transport.connect()

    assert fake.writes == ["", "exit", "secureadmin", "secret"]


def test_send_command_strips_echo_and_prompt(fake_serial) -> None:
    fake_serial(
        {
            **LOGIN_SCRIPT,
            "show user admin1": (
                "show user admin1\r\n"
                "User name = admin1,\r\n"
                "  Account lockout = Yes,\r\n"
                "ACSW01-> "
            ),
        }
    )
    transport = _transport()
    transport.connect()

    output = transport.send_command("show user admin1", timeout=2)

    assert output == "User name = admin1,\n  Account lockout = Yes,"


def test_send_command_pages_through_more_prompts(fake_serial) -> None:
    fake_serial(
        {
            **LOGIN_SCRIPT,
            "show log swlog": "show log swlog\r\nfirst page line\r\n--More--",
            # The pager is answered with a bare space (next page).
            " ": "\r\nsecond page line\r\nACSW01-> ",
        }
    )
    transport = _transport()
    transport.connect()

    output = transport.send_command("show log swlog", timeout=2)

    assert "first page line" in output
    assert "second page line" in output
    assert "More" not in output


def test_send_interactive_handles_reauth_prompt(fake_serial) -> None:
    fake_serial(
        {
            **LOGIN_SCRIPT,
            "show log swlog": "show log swlog\r\nPassword: ",
            "secret": "\r\nBanning station 192.168.1.50\r\nACSW01-> ",
        }
    )
    transport = _transport()
    transport.connect()

    output = transport.send_interactive(
        [
            ("show log swlog", "Password:", False),
            ("secret", r"^.*\->\s*$", True),
        ],
        timeout=2,
    )

    assert "Banning station 192.168.1.50" in output


def test_read_timeout_reports_the_port(fake_serial) -> None:
    fake_serial({**LOGIN_SCRIPT, "show system": ""})
    transport = _transport()
    transport.connect()

    with pytest.raises(ConnectionError, match="COM9"):
        transport.send_command("show system", timeout=1)


def test_close_logs_out_and_releases_the_port(fake_serial) -> None:
    fake = fake_serial({**LOGIN_SCRIPT, "exit": "\r\nlogin: "})
    transport = _transport()
    transport.connect()

    transport.close()

    assert fake.writes[-1] == "exit"
    assert fake.closed is True


def test_close_confirms_leaving_unsaved_changes(fake_serial) -> None:
    # Every testcase that configures anything leaves unsaved changes, so `exit`
    # comes back with a confirmation instead of the login prompt. Answering `y`
    # leaves without saving -- cleanup already restored the running config, and
    # `write memory` would persist whatever a half-finished run left behind.
    fake = fake_serial(
        {
            **LOGIN_SCRIPT,
            "exit": "\r\nChanges have not been saved. Exit anyway? (Y/N) ",
            "y": "\r\nlogin: ",
        }
    )
    transport = _transport()
    transport.connect()

    transport.close()

    assert fake.writes[-2:] == ["exit", "y"]
    assert fake.closed is True


def test_stale_session_logout_confirms_too(fake_serial) -> None:
    fake = fake_serial(
        {
            "": "\r\nACSW01-> ",
            "exit": "\r\nDo you want to exit without saving? (y/n): ",
            "y": "\r\nlogin: ",
            "secureadmin": "\r\nPassword: ",
            "secret": "\r\nACSW01-> ",
        }
    )
    transport = _transport()

    transport.connect()

    assert fake.writes[:4] == ["", "exit", "y", "secureadmin"]


# -- forced password change at first login (factory-reset switch) -----------
#
# A factory-reset OmniSwitch refuses to open a session until the password
# satisfies the policy. Rejecting a candidate re-opens the dialogue at "Enter
# current password:"; accepting one drops back to "login:". scripts/commission.py
# relies on being able to tell those two apart, which is the whole point of
# these tests -- the real dialogue only ever happens once per switch.


def _factory_transport():
    return _transport(auth_password="switch")


def test_first_login_reports_the_forced_change(fake_serial) -> None:
    fake = fake_serial(
        {
            "": "\r\nlogin: ",
            "secureadmin": "\r\nPassword: ",
            "switch": "\r\nPassword policy mismatch, please change password.\r\nEnter current password: ",
        }
    )
    transport = _factory_transport()
    transport.open_port_only()

    transport.await_login_prompt()
    response = transport.submit_login("secureadmin", "switch")

    assert "Password policy mismatch" in response
    assert fake.writes == ["", "secureadmin", "switch"]


def test_rejected_new_password_is_reported_with_the_switchs_reason(fake_serial) -> None:
    fake_serial(
        {
            "": "\r\nlogin: ",
            "secureadmin": "\r\nPassword: ",
            "switch": [
                "\r\nPassword policy mismatch, please change password.\r\nEnter current password: ",
                "\r\nEnter new password: ",
            ],
            "12#qweA": "\r\nRetype new password: ",
        }
    )
    transport = _factory_transport()
    transport.open_port_only()
    transport.await_login_prompt()
    transport.submit_login("secureadmin", "switch")

    # The retype is the second write of the same candidate, and the switch
    # answers it with the rejection plus a fresh dialogue.
    transport._connection.script["12#qweA"] = [
        "\r\nRetype new password: ",
        "\r\nPassword must contain at least 9 characters\r\nEnter current password: ",
    ]
    accepted, message = transport.change_password_at_login("switch", "12#qweA")

    assert accepted is False
    assert "at least 9 characters" in message


def test_accepted_new_password_returns_to_the_login_prompt(fake_serial) -> None:
    fake_serial(
        {
            "": "\r\nlogin: ",
            "secureadmin": "\r\nPassword: ",
            "switch": [
                "\r\nPassword policy mismatch, please change password.\r\nEnter current password: ",
                "\r\nEnter new password: ",
            ],
        }
    )
    transport = _factory_transport()
    transport.open_port_only()
    transport.await_login_prompt()
    transport.submit_login("secureadmin", "switch")

    transport._connection.script["12#qweASD"] = [
        "\r\nRetype new password: ",
        "\r\n\r\nOS6900 login: ",
    ]
    accepted, _message = transport.change_password_at_login("switch", "12#qweASD")

    assert accepted is True
