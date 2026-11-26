import pytest

from switchtest.infrastructure import session_probe
from switchtest.infrastructure.session_probe import check_ssh_session_expires

# What `show session config` actually answers on AOS. Note "Login Timer" and
# "Login Attempts": a substring search for "login" reads this live, perfectly
# normal output as "back at the login prompt".
SHOW_SESSION_CONFIG = """
Cli Default Prompt                   = ->
Cli Banner File Name                 = ,
Cli Inactivity Timer in minutes      = 1,
Ftp Banner File Name                 = ,
Ftp Inactivity Timer in minutes      = 4,
Http Inactivity Timer in minutes     = 4,
Http Banner File Name                = ,
Login Timer in seconds               = 55,
Maximum number of Login Attempts     = 3,
"""


class FakeTransport:
    def __init__(self, answers) -> None:
        self._answers = list(answers)
        self.closed = False

    def connect(self) -> None: ...

    def send_command(self, command: str, timeout: int = 30) -> str:
        answer = self._answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def close(self) -> None:
        self.closed = True


@pytest.fixture()
def install(monkeypatch):
    sleeps: list[int] = []
    monkeypatch.setattr(session_probe.time, "sleep", sleeps.append)

    def _install(*answers):
        transport = FakeTransport(answers)
        monkeypatch.setattr(session_probe, "SSHTransport", lambda **kwargs: transport)
        return transport, sleeps

    return _install


def test_a_session_still_answering_normally_is_not_expired(install) -> None:
    """The regression: this output contains "Login" twice and must still
    count as a live session."""
    install(SHOW_SESSION_CONFIG, SHOW_SESSION_CONFIG)

    expired, detail = check_ssh_session_expires("192.0.2.1", 22, "sessiontest", "x")

    assert expired is False
    assert "still usable" in detail


def test_a_command_that_fails_after_the_idle_counts_as_expired(install) -> None:
    transport, _ = install(SHOW_SESSION_CONFIG, EOFError("channel closed"))

    expired, _detail = check_ssh_session_expires("192.0.2.1", 22, "sessiontest", "x")

    assert expired is True
    assert transport.closed


@pytest.mark.parametrize("last_line", ["login :", "OS6900 login: ", "Password:"])
def test_ending_at_a_login_prompt_counts_as_expired(install, last_line) -> None:
    install(SHOW_SESSION_CONFIG, f"\nSession timed out\n{last_line}")

    expired, _detail = check_ssh_session_expires("192.0.2.1", 22, "sessiontest", "x")

    assert expired is True


def test_the_keepalive_runs_during_the_idle_but_not_after_it(install) -> None:
    _, sleeps = install(SHOW_SESSION_CONFIG, SHOW_SESSION_CONFIG)
    pokes: list[int] = []

    check_ssh_session_expires(
        "192.0.2.1",
        22,
        "sessiontest",
        "x",
        idle_seconds=75,
        keepalive=lambda: pokes.append(sum(sleeps)),
        keepalive_interval=20,
    )

    # The probe's own idle still adds up to the full 75s...
    assert sum(sleeps) == 75
    # ...while the caller's session is poked at 20/40/60s, never left idle as
    # long as the timeout under test.
    assert pokes == [20, 40, 60]
