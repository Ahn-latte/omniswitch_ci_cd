import logging

from switchtest.infrastructure.ssh.client import _configure_paramiko_logging


def _capture(records):
    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())
    return Capture()


def _logger(records):
    _configure_paramiko_logging()
    log = logging.getLogger("paramiko.transport")
    log.handlers = [_capture(records)]
    log.setLevel(logging.DEBUG)
    log.propagate = False
    return log


BANNER_TRACEBACK = [
    "Exception (client): Error reading SSH protocol banner",
    "Traceback (most recent call last):",
    '  File "paramiko/transport.py", line 2213, in _check_banner',
    "    buf = self.packetizer.readline(timeout)",
    "EOFError",
    "",
    "During handling of the above exception, another exception occurred:",
    "",
    "paramiko.ssh_exception.SSHException: Error reading SSH protocol banner",
]


def test_banner_traceback_is_suppressed_line_by_line():
    """paramiko logs a traceback as one record per line, so matching the
    message only hid the two lines naming the banner and left the rest --
    which is what still looked like a crash mid-run."""
    records: list[str] = []
    log = _logger(records)

    for line in BANNER_TRACEBACK:
        log.error(line)

    assert records == []


def test_ordinary_paramiko_logging_survives():
    records: list[str] = []
    log = _logger(records)

    for line in BANNER_TRACEBACK:
        log.error(line)
    log.info("Connected (version 2.0, client OpenSSH_8.0)")
    log.error("Authentication (password) failed.")

    assert records == [
        "Connected (version 2.0, client OpenSSH_8.0)",
        "Authentication (password) failed.",
    ]
