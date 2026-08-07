import socket
import threading

import pytest

from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.api_probe import check_api_unreachable


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_closed_port_reads_as_unreachable() -> None:
    # Nothing is listening, which is what a disabled ip service looks like.
    unreachable, detail = check_api_unreachable("127.0.0.1", _free_port(), timeout=5)

    assert unreachable
    assert "127.0.0.1" in detail


def test_a_listener_that_answers_reads_as_reachable() -> None:
    # Any HTTP answer means the service is up -- even an error status.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def respond() -> None:
        connection, _ = server.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")

    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    try:
        unreachable, detail = check_api_unreachable("127.0.0.1", port, timeout=5)
    finally:
        thread.join(timeout=5)
        server.close()

    assert not unreachable
    assert "401" in detail


def test_target_and_port_are_required() -> None:
    with pytest.raises(ValidationExecutionError):
        check_api_unreachable("", 443)
    with pytest.raises(ValidationExecutionError):
        check_api_unreachable("127.0.0.1", 0)
