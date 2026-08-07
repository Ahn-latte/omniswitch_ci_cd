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


class FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture()
def fake_nmap(monkeypatch):
    calls: list[list[str]] = []

    def install(output: str):
        def fake_run(command, **kwargs):
            calls.append(command)
            return FakeCompleted(stdout=output)

        monkeypatch.setattr(nmap_module.subprocess, "run", fake_run)
        return calls

    return install


def test_top_ports_scan_builds_the_agreed_command(fake_nmap) -> None:
    calls = fake_nmap(CLOSED_OUTPUT)

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
        "192.168.1.1",
    ]


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


def test_scan_timeout_explains_the_udp_cost(monkeypatch) -> None:
    def slow(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 600)

    monkeypatch.setattr(nmap_module.subprocess, "run", slow)

    with pytest.raises(ValidationExecutionError, match="ICMP rate limiting"):
        scan_top_ports("192.168.1.1", timeout=600)


def test_missing_nmap_is_reported(monkeypatch) -> None:
    def missing(command, **kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(nmap_module.subprocess, "run", missing)

    with pytest.raises(ValidationExecutionError, match="nmap"):
        scan_top_ports("192.168.1.1")
