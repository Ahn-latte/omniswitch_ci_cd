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
    drop the connection right there. That is exactly what "SSH1 is not
    accepted" looks like on the wire.

    Returns (rejected, detail). True means the connection was closed or reset
    after the client's identification line went out -- a definite refusal.
    False covers everything else, including "the socket is still open and
    nothing happened", on purpose: a non-closure that never resolves either
    way is not proof the server actually turned the legacy protocol away.
    """
    if not target:
        raise ValidationExecutionError("Legacy-SSH validation requires a target")
    if not port:
        raise ValidationExecutionError("Legacy-SSH validation requires a port")
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            server_banner = _read_line(sock)
            sock.sendall(f"{client_banner}\r\n".encode("ascii"))
            try:
                remainder = sock.recv(256)
            except (TimeoutError, socket.timeout):
                elapsed = time.monotonic() - started
                return False, (
                    f"server banner {server_banner!r}; sent {client_banner!r}, but the "
                    f"connection was still open {elapsed:.2f}s later with no response -- "
                    f"not a confirmed rejection"
                )
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
                return True, (
                    f"server banner {server_banner!r}; sent {client_banner!r}, connection "
                    f"reset: {exc}"
                )
            if remainder == b"":
                return True, (
                    f"server banner {server_banner!r}; sent {client_banner!r}, server closed "
                    f"the connection"
                )
            return False, (
                f"server banner {server_banner!r}; sent {client_banner!r}, server kept "
                f"talking instead of closing: {remainder!r}"
            )
    except OSError as exc:
        raise ValidationExecutionError(f"Could not connect to {target}:{port}: {exc}") from exc


def _read_line(sock: socket.socket) -> str:
    buffer = b""
    while not buffer.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        buffer += chunk
    return buffer.decode("ascii", errors="replace").strip()
