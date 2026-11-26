import socket
import threading

import pytest

from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.ssh_probe import check_legacy_ssh_rejected


def _serve_once(behaviour):
    """A one-connection SSH-ish server on localhost: sends its banner, reads
    the client's identification line, then does whatever `behaviour` says."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    release = threading.Event()

    def run():
        conn, _ = listener.accept()
        with conn:
            conn.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
            buffer = b""
            while not buffer.endswith(b"\n"):
                chunk = conn.recv(1)
                if not chunk:
                    break
                buffer += chunk
            behaviour(conn, release)
        listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return port, release, thread


def test_a_plaintext_refusal_followed_by_a_close_is_a_rejection() -> None:
    """What an OpenSSH-derived sshd actually does with a 1.x identification:
    says why, then hangs up. The old single-read probe failed on this."""
    def refuse(conn, _release):
        conn.sendall(b"Protocol major versions differ.\r\n")

    port, _release, thread = _serve_once(refuse)

    rejected, detail = check_legacy_ssh_rejected("127.0.0.1", port, timeout=5)

    thread.join(5)
    assert rejected is True
    assert "Protocol major versions differ." in detail


def test_a_silent_close_is_a_rejection() -> None:
    port, _release, thread = _serve_once(lambda conn, release: None)

    rejected, _detail = check_legacy_ssh_rejected("127.0.0.1", port, timeout=5)

    thread.join(5)
    assert rejected is True


def test_binary_protocol_data_and_an_open_connection_is_not_a_rejection() -> None:
    """A key-exchange packet means the server is trying to carry on."""
    def carry_on(conn, release):
        conn.sendall(b"\x00\x00\x01\x2c\x0a\x14" + bytes(range(16)))
        release.wait(5)

    port, release, thread = _serve_once(carry_on)

    rejected, detail = check_legacy_ssh_rejected("127.0.0.1", port, timeout=1)

    release.set()
    thread.join(5)
    assert rejected is False
    assert "still open" in detail


def test_closing_after_binary_data_is_not_a_clean_refusal() -> None:
    def kex_then_close(conn, _release):
        conn.sendall(b"\x00\x00\x01\x2c\x0a\x14" + bytes(range(16)))

    port, _release, thread = _serve_once(kex_then_close)

    rejected, detail = check_legacy_ssh_rejected("127.0.0.1", port, timeout=5)

    thread.join(5)
    assert rejected is False
    assert "binary" in detail


def test_an_unreachable_port_is_an_error_not_a_rejection() -> None:
    """Nothing listening is not evidence about SSH-1 at all."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    with pytest.raises(ValidationExecutionError, match="Could not connect"):
        check_legacy_ssh_rejected("127.0.0.1", port, timeout=2)
