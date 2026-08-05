import socket
import time

from switchtest.exceptions import ValidationExecutionError


def probe_tcp(target: str, port: int, timeout: int = 15) -> tuple[bool, str]:
    """Try to open a TCP connection; report whether it was blocked.

    Returns (blocked, detail). "Blocked" means the connection could not be
    established -- either dropped (timeout, what an IP ban looks like: the
    switch stops answering rather than refusing) or actively refused.

    Distinct from the `port_closed` validation, which asks nmap whether a
    service is listening at all. This asks whether *this machine* can still
    reach a service that is otherwise up, which is what an IP-level ban
    changes.
    """
    if not target:
        raise ValidationExecutionError("TCP probe validation requires a target")
    if not port:
        raise ValidationExecutionError("TCP probe validation requires a port")
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            pass
    except TimeoutError:
        return True, f"connection to {target}:{port} timed out after {timeout}s (dropped)"
    except OSError as exc:
        return True, f"connection to {target}:{port} failed: {exc}"
    elapsed = time.monotonic() - started
    return False, f"connection to {target}:{port} succeeded in {elapsed:.2f}s"
