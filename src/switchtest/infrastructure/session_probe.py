import time

from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.ssh.client import SSHTransport


def check_ssh_session_expires(
    host: str,
    port: int,
    username: str,
    password: str,
    idle_seconds: int = 75,
    timeout: int = 15,
) -> tuple[bool, str]:
    """Open a fresh SSH session, confirm it is actually up, sit idle past the
    switch's configured inactivity timeout, then try one more command.

    Returns (expired, detail). True means the second command failed outright
    or the session was reset to a fresh login prompt -- the switch actually
    closed the idle session, not just something that is configured to
    happen. False means the session was still usable, i.e. the timeout was
    not enforced in practice.

    A brand-new connection, never the caller's own: AOS allows only one
    session per account across every transport, so this needs an account the
    driver's own session (secureadmin, most commonly) is not already holding
    open -- a throwaway account the testcase's own setup creates is the
    usual choice.
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
        time.sleep(idle_seconds)
        try:
            after_idle = transport.send_command("show session config", timeout=timeout)
        except Exception as exc:
            return True, (
                f"session as {username!r} was no longer usable after {idle_seconds}s idle: "
                f"{type(exc).__name__}: {exc}"
            )
        if _looks_like_a_fresh_login(after_idle):
            return True, (
                f"session as {username!r} was reset to a login prompt after {idle_seconds}s "
                f"idle: {after_idle!r}"
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


def _looks_like_a_fresh_login(output: str) -> bool:
    lowered = output.lower()
    return "login" in lowered or "password" in lowered
