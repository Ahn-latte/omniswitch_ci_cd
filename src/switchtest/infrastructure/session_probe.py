import re
import time
from typing import Callable

from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.ssh.client import SSHTransport

# A prompt *line* asking to log in again -- "login :", "Login:", "Password:".
# Judged on the last line only, never by a substring anywhere in the output:
# the very command this probe sends (`show session config`) answers with
# "Login Timer in seconds" and "Maximum number of Login Attempts", so a
# substring search reads a perfectly live session as a logged-out one and the
# check passes on a switch that never enforces the timeout at all.
_LOGIN_PROMPT_LINE = re.compile(r"(?i)\b(?:login|password)\s*:\s*$")


def check_ssh_session_expires(
    host: str,
    port: int,
    username: str,
    password: str,
    idle_seconds: int = 75,
    timeout: int = 15,
    keepalive: Callable[[], object] | None = None,
    keepalive_interval: int = 20,
) -> tuple[bool, str]:
    """Open a fresh SSH session, confirm it is actually up, sit idle past the
    switch's configured inactivity timeout, then try one more command.

    Returns (expired, detail). True means the second command failed outright
    or came back at a login prompt -- the switch actually closed the idle
    session. False means the session was still usable, i.e. the timeout was
    not enforced in practice.

    A brand-new connection, never the caller's own: AOS allows only one
    session per account across every transport, so this needs an account the
    driver's own session is not already holding open -- a throwaway account
    the testcase's own setup creates is the usual choice.

    `keepalive` exists because the timeout being tested applies to the
    caller's session too. Left idle for the same `idle_seconds`, the driver's
    own session would be disconnected along with the probe's, and the
    testcase's cleanup -- the step that puts the timeout back -- would then
    run against a dead session: the device marked UNSAFE, the rest of the
    suite stopped, and the switch left at the short timeout. So the caller's
    session is poked every `keepalive_interval` seconds while only the
    probe's session stays genuinely idle.
    """
    if not host:
        raise ValidationExecutionError("Session-expiry validation requires a target")
    if not username:
        raise ValidationExecutionError("Session-expiry validation requires 'session_username'")
    transport = SSHTransport(
        host=host,
        port=port,
        auth_username=username,
        auth_password=password,
        timeout_socket=timeout,
        timeout_ops=timeout,
    )
    transport.connect()
    try:
        transport.send_command("show session config", timeout=timeout)
        _idle(idle_seconds, keepalive, keepalive_interval)
        try:
            after_idle = transport.send_command("show session config", timeout=timeout)
        except Exception as exc:
            return True, (
                f"session as {username!r} was no longer usable after {idle_seconds}s idle: "
                f"{type(exc).__name__}: {exc}"
            )
        if _ends_at_login_prompt(after_idle):
            return True, (
                f"session as {username!r} was back at a login prompt after {idle_seconds}s "
                f"idle: {after_idle.strip()[-200:]!r}"
            )
        return False, (
            f"session as {username!r} was still usable after {idle_seconds}s idle -- expected "
            f"the inactivity timeout to have closed it"
        )
    finally:
        try:
            transport.close()
        except Exception:
            pass


def _idle(seconds: int, keepalive: Callable[[], object] | None, interval: int) -> None:
    remaining = seconds
    while remaining > 0:
        chunk = min(interval, remaining)
        time.sleep(chunk)
        remaining -= chunk
        if keepalive is not None and remaining > 0:
            keepalive()


def _ends_at_login_prompt(output: str) -> bool:
    for line in reversed(output.splitlines()):
        if line.strip():
            return _LOGIN_PROMPT_LINE.search(line) is not None
    return False
