import subprocess

import pytest

from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure import nmap as nmap_module
from switchtest.infrastructure.nmap import scan_top_ports

OPEN_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org )
Initiating SYN Stealth Scan at 13:01
Nmap scan report for 192.168.1.1
Host is up (0.0012s latency).
Not shown: 97 closed tcp ports (reset), 99 open|filtered udp ports (no-response)
PORT    STATE         SERVICE
22/tcp  open          ssh
443/tcp open          https
161/udp open|filtered snmp
Nmap done: 1 IP address (1 host up) scanned in 42.11 seconds
"""

CLOSED_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0013s latency).
All 200 scanned ports on 192.168.1.1 are closed
Nmap done: 1 IP address (1 host up) scanned in 38.02 seconds
"""

UNPRIVILEGED_OUTPUT = """You requested a scan type which requires root privileges.
QUITTING!
"""


class FakePipe:
    """nmap's stdout: iterating it hands back one line at a time, which is what
    lets the reader thread report progress before the scan has finished."""

    def __init__(self, output: str) -> None:
        self._lines = output.splitlines(keepends=True)
        self.closed = False

    def __iter__(self):
        for line in self._lines:
            if self.closed:
                return
            yield line

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    def __init__(self, output: str, hangs: bool = False) -> None:
        self.stdout = FakePipe(output)
        self._hangs = hangs
        self.killed = False

    def wait(self, timeout=None):
        # Only the deadline-bearing wait can time out; the one after kill() is
        # just reaping the child and must return.
        if self._hangs and timeout is not None:
            raise subprocess.TimeoutExpired("nmap", timeout)
        return 0

    def kill(self) -> None:
        self.killed = True
        self.stdout.close()


@pytest.fixture()
def fake_nmap(monkeypatch):
    calls: list[list[str]] = []
    processes: list[FakeProcess] = []

    def install(output: str, hangs: bool = False):
        def fake_popen(command, **kwargs):
            calls.append(command)
            process = FakeProcess(output, hangs=hangs)
            processes.append(process)
            return process

        monkeypatch.setattr(nmap_module.subprocess, "Popen", fake_popen)
        return calls, processes

    return install


def test_top_ports_scan_builds_the_agreed_command(fake_nmap) -> None:
    calls, _ = fake_nmap(CLOSED_OUTPUT)

    scan_top_ports("192.168.1.1", top_ports=100)

    assert calls[0] == [
        "nmap",
        "-Pn",
        "-sS",
        "-sU",
        "--top-ports",
        "100",
        "-T4",
        "-v",
        # Without this nmap stays quiet until a phase already looks slow, and
        # there would be nothing to show while the scan runs.
        "--stats-every",
        "2s",
        "192.168.1.1",
    ]


def test_scan_output_is_streamed_to_the_progress_callback(fake_nmap) -> None:
    fake_nmap(OPEN_OUTPUT)
    seen: list[str] = []

    scan_top_ports("192.168.1.1", on_progress=seen.append)

    # Every line, in order, with the newlines stripped -- the renderer decides
    # which of them are worth showing.
    assert seen[0] == "Starting Nmap 7.94 ( https://nmap.org )"
    assert "Initiating SYN Stealth Scan at 13:01" in seen
    assert len(seen) == len(OPEN_OUTPUT.splitlines())


def test_a_scan_without_a_progress_callback_still_works(fake_nmap) -> None:
    fake_nmap(CLOSED_OUTPUT)

    open_ports, summary = scan_top_ports("192.168.1.1", on_progress=None)

    assert open_ports == []
    assert "All 200 scanned ports" in summary


def test_top_ports_scan_reports_no_open_ports(fake_nmap) -> None:
    fake_nmap(CLOSED_OUTPUT)

    open_ports, summary = scan_top_ports("192.168.1.1")

    assert open_ports == []
    assert "All 200 scanned ports" in summary


def test_top_ports_scan_collects_only_open_ports(fake_nmap) -> None:
    fake_nmap(OPEN_OUTPUT)

    open_ports, summary = scan_top_ports("192.168.1.1")

    # open|filtered is what a silent UDP port looks like -- not "open".
    assert open_ports == ["22/tcp open (ssh)", "443/tcp open (https)"]
    assert "161/udp open|filtered snmp" in summary
    # The verbose progress lines are dropped so the report stays readable.
    assert "Initiating SYN Stealth Scan" not in summary


def test_unprivileged_scan_errors_instead_of_looking_clean(fake_nmap) -> None:
    # -sS/-sU need raw sockets; an unprivileged run must not be mistaken for
    # "nothing is open".
    fake_nmap(UNPRIVILEGED_OUTPUT)

    with pytest.raises(ValidationExecutionError, match="unprivileged"):
        scan_top_ports("192.168.1.1")


def test_scan_timeout_explains_the_udp_cost_and_kills_the_child(fake_nmap) -> None:
    _, processes = fake_nmap(CLOSED_OUTPUT, hangs=True)

    with pytest.raises(ValidationExecutionError, match="ICMP rate limiting"):
        scan_top_ports("192.168.1.1", timeout=600)

    # An nmap left running would keep scanning the switch after the testcase
    # has moved on.
    assert processes[0].killed


def test_missing_nmap_is_reported(monkeypatch) -> None:
    def missing(command, **kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(nmap_module.subprocess, "Popen", missing)

    with pytest.raises(ValidationExecutionError, match="nmap"):
        scan_top_ports("192.168.1.1")
