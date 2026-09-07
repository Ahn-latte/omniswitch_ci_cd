"""Listen on the wire for an incoming SNMP trap/notification datagram.

Proves a trap was actually *received*, not just that the switch is
configured to send one. `check_snmpv3_account_station.yaml` (TC-SM-42)
creates the trap station and audits the CLI commands that set it up, but
until this module existed nothing in this project ever listened on the wire
for a real trap packet -- a station created and enabled, but that silently
never fired anything, still passed. `snmp_trap_received` closes that gap.

Binding UDP/162 needs a low-port privilege on most platforms (elevated
Administrator on Windows, root on Linux) -- the same requirement nmap's
-sS/-sU already has elsewhere in this project.
"""

from contextlib import AbstractContextManager
from dataclasses import dataclass
import socket
import time
from typing import Optional

from switchtest.exceptions import ValidationExecutionError

DEFAULT_TRAP_PORT = 162

# BER's SEQUENCE tag: every SNMP message (v1/v2c/v3 alike) is one, so a
# datagram that doesn't start with this byte is not SNMP-shaped at all --
# worth telling apart from "arrived but this decoder couldn't read it".
_BER_SEQUENCE_TAG = 0x30


@dataclass
class ReceivedTrap:
    source_ip: str
    payload: bytes
    # Both best-effort: read from the SNMPv3 message *header*, which stays
    # cleartext even when the PDU itself is authPriv-encrypted (RFC 3412/3414),
    # so no auth/privacy key is needed to read them. None if decoding failed
    # or the trap was v1/v2c (no msgUserName) -- that does not by itself mean
    # nothing arrived, only that this project's minimal decoder couldn't say
    # more about what did.
    version: Optional[str] = None
    username: Optional[str] = None


class TrapListener(AbstractContextManager):
    """A bound UDP socket, as a context manager.

    Usage is deliberately bind-then-trigger-then-wait, each its own step,
    because the ordering matters: the socket must be bound *before* whatever
    CLI action is expected to make the switch send a trap, or the switch can
    send it before this process is listening and the trap is lost to a race
    rather than a real failure.

        with TrapListener(port) as listener:
            driver.apply_config(trigger_commands)   # provoke the trap
            trap = listener.wait_for(timeout, expected_source=target)
    """

    def __init__(self, port: int = DEFAULT_TRAP_PORT, bind_host: str = "0.0.0.0") -> None:
        self._port = port
        self._bind_host = bind_host
        self._sock: socket.socket | None = None

    def __enter__(self) -> "TrapListener":
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            raise ValidationExecutionError(f"Could not open a UDP socket: {exc}") from exc
        try:
            sock.bind((self._bind_host, self._port))
        except PermissionError as exc:
            sock.close()
            raise ValidationExecutionError(
                f"Binding UDP/{self._port} needs an elevated shell (Administrator on "
                f"Windows, root on Linux) -- same requirement as nmap's -sS/-sU elsewhere "
                f"in this project"
            ) from exc
        except OSError as exc:
            sock.close()
            raise ValidationExecutionError(
                f"Could not bind UDP/{self._port} on {self._bind_host}: {exc} "
                f"(something else already listening there? a real SNMP trap daemon "
                f"running on this PC would collide with this check)"
            ) from exc
        self._sock = sock
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def wait_for(self, timeout: int, expected_source: str | None = None) -> Optional[ReceivedTrap]:
        """Block for up to `timeout` seconds for one matching datagram.

        When `expected_source` is set, datagrams from anywhere else are
        drained and ignored rather than ending the wait early or being
        mistaken for the trap under test -- other devices on the same subnet
        legitimately send unrelated traffic to 162.
        """
        if self._sock is None:
            raise ValidationExecutionError("TrapListener.wait_for() called outside its `with` block")
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._sock.settimeout(remaining)
            try:
                payload, (source_ip, _source_port) = self._sock.recvfrom(65535)
            except socket.timeout:
                return None
            except OSError as exc:
                raise ValidationExecutionError(f"UDP receive on port {self._port} failed: {exc}") from exc
            if expected_source and source_ip != expected_source:
                continue
            return _parse(source_ip, payload)


def _parse(source_ip: str, payload: bytes) -> ReceivedTrap:
    trap = ReceivedTrap(source_ip=source_ip, payload=payload)
    if not payload or payload[0] != _BER_SEQUENCE_TAG:
        return trap
    try:
        trap.version, trap.username = _decode_header(payload)
    except Exception:
        # Best-effort only. The primary proof -- a BER-shaped datagram
        # arrived from the switch's own address right after this project
        # provoked it -- already stands on the caller's source-IP match; a
        # header this decoder can't parse is still evidence of receipt, not
        # grounds to fail the check.
        pass
    return trap


def _decode_header(payload: bytes) -> tuple[str, str | None]:
    """Read just the SNMP message version, and for v3 the USM `msgUserName`."""
    from pyasn1.codec.ber import decoder as ber_decoder

    message, _rest = ber_decoder.decode(payload)
    version = int(message[0])
    version_name = {0: "v1", 1: "v2c", 3: "v3"}.get(version, f"unknown({version})")
    if version != 3:
        return version_name, None
    # RFC 3412 SNMPv3Message: [0]=msgVersion [1]=msgGlobalData [2]=msgSecurityParameters
    # (an OCTET STRING wrapping a further BER-encoded UsmSecurityParameters).
    security_params_bytes = bytes(message[2])
    usm, _rest = ber_decoder.decode(security_params_bytes)
    # RFC 3414 UsmSecurityParameters: engineID, engineBoots, engineTime,
    # msgUserName, msgAuthenticationParameters, msgPrivacyParameters.
    username = str(usm[3])
    return version_name, username
