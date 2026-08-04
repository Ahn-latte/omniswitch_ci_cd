import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

from switchtest.exceptions import ValidationExecutionError

_TLS_VERSION_NAMES = {
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}


def capture_tls_version(interface: str, target: str, port: int, duration: int = 10) -> tuple[str, str]:
    """Capture the switch's TLS ServerHello with tshark and report the
    negotiated version. Since tshark only sees traffic that actually occurs
    during the capture window, this also triggers a real handshake against
    `target:port` itself (a certificate-verification-skipping TLS client
    connection, matching this project's default trust of switches' self-signed
    certs) partway through.

    Returns (version_name, raw_hex), e.g. ("TLS 1.2", "0x0303").

    Note: TLS 1.3's ServerHello sets this legacy version field to 0x0303 for
    backward compatibility (the real version is in a supported_versions
    extension this doesn't parse), so a TLS 1.3 handshake would misreport as
    TLS 1.2 here. Not a concern for AOS8 WebView, which doesn't offer 1.3.
    """
    if not interface:
        raise ValidationExecutionError(
            "TLS capture validation requires a capture interface "
            "(run `tshark -D` to list interfaces and set SWITCHTEST_CAPTURE_INTERFACE)"
        )
    if not target:
        raise ValidationExecutionError("TLS capture validation requires a target")
    if not port:
        raise ValidationExecutionError("TLS capture validation requires a port")

    with tempfile.TemporaryDirectory() as tmp_dir:
        pcap_path = Path(tmp_dir) / "capture.pcapng"
        capture_cmd = [
            "tshark",
            "-i",
            interface,
            "-f",
            f"host {target} and tcp port {port}",
            "-w",
            str(pcap_path),
            "-a",
            f"duration:{duration}",
        ]
        try:
            capture = subprocess.Popen(capture_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except FileNotFoundError as exc:
            raise ValidationExecutionError("tshark utility is not available") from exc

        time.sleep(1.5)  # let tshark/Npcap attach to the interface before generating traffic
        handshake_error = _perform_tls_handshake(target, port)

        try:
            _, stderr = capture.communicate(timeout=duration + 10)
        except subprocess.TimeoutExpired as exc:
            capture.kill()
            raise ValidationExecutionError(f"tshark capture did not exit within {duration + 10}s") from exc

        if capture.returncode != 0:
            raise ValidationExecutionError(f"tshark capture failed: {stderr.strip()}")
        if handshake_error:
            raise ValidationExecutionError(f"Could not connect to trigger a TLS handshake: {handshake_error}")

        read_cmd = [
            "tshark",
            "-r",
            str(pcap_path),
            "-Y",
            f"ip.addr=={target} and tcp.port=={port} and tls.handshake.type==2",
            "-T",
            "fields",
            "-e",
            "tls.handshake.version",
        ]
        read = subprocess.run(read_cmd, capture_output=True, text=True, check=False)
        lines = [line for line in read.stdout.strip().splitlines() if line]
        if not lines:
            raise ValidationExecutionError(
                f"No TLS ServerHello captured for {target}:{port} within {duration}s "
                f"(tshark stderr: {read.stderr.strip()})"
            )
        raw_hex = lines[0].strip()
        version_name = _TLS_VERSION_NAMES.get(raw_hex, f"unknown ({raw_hex})")
        return version_name, raw_hex


def _perform_tls_handshake(target: str, port: int) -> str | None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target):
                pass
    except OSError as exc:
        return str(exc)
    return None
