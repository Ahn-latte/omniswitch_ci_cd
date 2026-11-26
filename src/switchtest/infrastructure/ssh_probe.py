import socket
import time

from switchtest.exceptions import ValidationExecutionError

DEFAULT_LEGACY_BANNER = "SSH-1.5-switchtest_1.0"


def check_legacy_ssh_rejected(
    target: str, port: int, client_banner: str = DEFAULT_LEGACY_BANNER, timeout: int = 15
) -> tuple[bool, str]:
    """Speak only the SSH version-exchange line, claiming protocol 1.5, and
    report whether the server actually refuses it.

    A real SSH-1 handshake can't be attempted from here: OpenSSH removed
    protocol-1 support from its own client in 7.6 (2017), and there is no
    maintained SSH1 client library to fall back to. What this probes instead
    is the version-exchange line every SSH connection starts with (RFC 4253
    4.2), before any key exchange -- a server that only implements protocol 2
    has no way to continue a handshake claiming 1.x, so it has to reject or
    drop the connection right there.

    The server is read until it closes or `timeout` runs out, not just once:
    an OpenSSH-derived sshd answers a 1.x identification with a plaintext
    "Protocol major versions differ." and *then* closes, so the first read
    returns that sentence. Treating any data at all as "the server kept
    talking" failed exactly the switches that refuse correctly.

    Returns (rejected, detail). True: the connection closed (or was reset)
    having sent nothing but readable text -- a refusal, with whatever reason
    it gave. False covers everything else, on purpose: still open when time
    ran out, or closing after sending binary protocol data (a key exchange
    packet means the server tried to carry on). Neither proves the legacy
    protocol was turned away.
    """
    if not target:
        raise ValidationExecutionError("Legacy-SSH validation requires a target")
    if not port:
        raise ValidationExecutionError("Legacy-SSH validation requires a port")
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            server_banner = _read_line(sock)
            sock.sendall(f"{client_banner}\r\n".encode("ascii"))
            received, closed, how = _read_until_closed(sock, timeout)
    except OSError as exc:
        raise ValidationExecutionError(f"Could not connect to {target}:{port}: {exc}") from exc

    said = received.decode("ascii", errors="replace").strip()
    prefix = f"server banner {server_banner!r}; sent {client_banner!r}"
    if closed and _is_text(received):
        reason = f", saying {said!r}" if said else ""
        return True, f"{prefix}; server {how}{reason}"
    if closed:
        return False, (
            f"{prefix}; server {how}, but only after sending binary protocol data "
            f"({len(received)} bytes) -- it tried to continue the handshake, not a clean refusal"
        )
    return False, (
        f"{prefix}; connection still open after {timeout}s"
        + (f" (server sent {received[:80]!r})" if received else " with no response")
        + " -- not a confirmed rejection"
    )


def _read_until_closed(sock: socket.socket, timeout: float) -> tuple[bytes, bool, str]:
    received = b""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return received, False, "kept the connection open"
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(4096)
        except (TimeoutError, socket.timeout):
            return received, False, "kept the connection open"
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
            return received, True, f"reset the connection ({exc})"
        if not chunk:
            return received, True, "closed the connection"
        received += chunk


def _is_text(data: bytes) -> bool:
    return all(32 <= byte < 127 or byte in (9, 10, 13) for byte in data)


def _read_line(sock: socket.socket) -> str:
    buffer = b""
    while not buffer.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        buffer += chunk
    return buffer.decode("ascii", errors="replace").strip()
