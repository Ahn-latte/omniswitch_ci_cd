import subprocess

import pytest

from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure import winscp_probe
from switchtest.infrastructure.winscp_probe import check_sftp_download_blocked


class FakeCompletedProcess:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture(autouse=True)
def fake_winscp_on_path(monkeypatch):
    monkeypatch.setattr(winscp_probe.shutil, "which", lambda name: r"C:\WinSCP\winscp.com")


def test_passes_when_the_exit_code_is_nonzero_and_nothing_downloaded(monkeypatch) -> None:
    monkeypatch.setattr(
        winscp_probe.subprocess,
        "run",
        lambda command, **kwargs: FakeCompletedProcess(1, stderr="Access denied.\n"),
    )
    blocked, detail = check_sftp_download_blocked(
        "192.0.2.1", 22, "wsftpread", "x", "/flash/system/userTable11"
    )
    assert blocked is True
    assert "Access denied" in detail


def test_fails_when_the_file_actually_lands(monkeypatch) -> None:
    def fake_run(command, **kwargs):
        # The script's `get` target is the last quoted path on the "get" line
        # of the script file passed via /script=; write to it so this test
        # doesn't need to parse the script to find the same path back out.
        script_path = next(part.split("=", 1)[1] for part in command if part.startswith("/script="))
        for line in open(script_path, encoding="utf-8"):
            if line.startswith("get "):
                local_target = line.rsplit('"', 2)[1]
                with open(local_target, "wb") as fh:
                    fh.write(b"not actually secret, just a fixture")
        return FakeCompletedProcess(0)

    monkeypatch.setattr(winscp_probe.subprocess, "run", fake_run)
    blocked, detail = check_sftp_download_blocked(
        "192.0.2.1", 22, "wsftpadmin", "x", "/flash/system/userTable11"
    )
    assert blocked is False
    assert "downloaded" in detail


def test_inconclusive_when_exit_is_zero_but_nothing_downloaded(monkeypatch) -> None:
    monkeypatch.setattr(
        winscp_probe.subprocess, "run", lambda command, **kwargs: FakeCompletedProcess(0)
    )
    blocked, detail = check_sftp_download_blocked(
        "192.0.2.1", 22, "wsftpread", "x", "/flash/system/userTable11"
    )
    assert blocked is False
    assert "inconclusive" in detail


def test_credentials_go_into_the_script_file_not_argv(monkeypatch) -> None:
    seen_commands: list = []

    def fake_run(command, **kwargs):
        seen_commands.append(command)
        return FakeCompletedProcess(1)

    monkeypatch.setattr(winscp_probe.subprocess, "run", fake_run)
    check_sftp_download_blocked(
        "192.0.2.1", 22, "wsftpread", "correct-horse-battery-staple", "/flash/system/userTable11"
    )
    assert not any("correct-horse-battery-staple" in part for part in seen_commands[0])


def test_missing_winscp_is_reported(monkeypatch) -> None:
    monkeypatch.setattr(winscp_probe.shutil, "which", lambda name: None)
    # Also rule out a real install on this machine's default paths, so the
    # test's outcome doesn't depend on whether WinSCP happens to be present.
    monkeypatch.setattr(winscp_probe, "_DEFAULT_INSTALL_DIRS", ())
    with pytest.raises(ValidationExecutionError, match="winscp.com"):
        check_sftp_download_blocked("192.0.2.1", 22, "wsftpread", "x", "/flash/system/userTable11")


def test_finds_winscp_in_a_default_install_dir_when_not_on_path(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(winscp_probe.shutil, "which", lambda name: None)
    fake_install_dir = tmp_path / "WinSCP"
    fake_install_dir.mkdir()
    (fake_install_dir / "winscp.com").write_text("not a real binary, just a fixture")
    monkeypatch.setattr(winscp_probe, "_DEFAULT_INSTALL_DIRS", (str(fake_install_dir),))

    seen_commands: list = []

    def fake_run(command, **kwargs):
        seen_commands.append(command)
        return FakeCompletedProcess(1)

    monkeypatch.setattr(winscp_probe.subprocess, "run", fake_run)
    check_sftp_download_blocked("192.0.2.1", 22, "wsftpread", "x", "/flash/system/userTable11")
    assert seen_commands[0][0] == str(fake_install_dir / "winscp.com")


def test_timeout_is_reported(monkeypatch) -> None:
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired("winscp.com", kwargs.get("timeout", 0))

    monkeypatch.setattr(winscp_probe.subprocess, "run", fake_run)
    with pytest.raises(ValidationExecutionError, match="did not finish"):
        check_sftp_download_blocked("192.0.2.1", 22, "wsftpread", "x", "/flash/system/userTable11")


def test_requires_a_target() -> None:
    with pytest.raises(ValidationExecutionError, match="target"):
        check_sftp_download_blocked("", 22, "wsftpread", "x", "/flash/system/userTable11")


def test_requires_a_username() -> None:
    with pytest.raises(ValidationExecutionError, match="username"):
        check_sftp_download_blocked("192.0.2.1", 22, "", "x", "/flash/system/userTable11")


def test_requires_a_remote_path() -> None:
    with pytest.raises(ValidationExecutionError, match="path"):
        check_sftp_download_blocked("192.0.2.1", 22, "wsftpread", "x", "")
