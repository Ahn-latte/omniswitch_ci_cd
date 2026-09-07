"""Unit tests for TrapListener's socket behaviour.

These exercise real UDP sockets on loopback -- no fake transport needed,
since binding a high port and sending a datagram to it is fast and hermetic
in a test process. The SNMPv3 header decode (`_decode_header`) needs pyasn1,
which comes in transitively via pysnmp (a base dependency of this project,
per pyproject.toml) -- if your environment is missing it, only the decode
test below will fail to import; every other test here needs nothing but the
standard library.
"""

import socket

import pytest

from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.trap_listener import TrapListener, _parse


def _free_port() -> int:
    """Ask the OS for a port nothing is using, so tests never collide with
    each other or with a real SNMP trap daemon on the machine running them."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_wait_for_returns_none_on_timeout() -> None:
    port = _free_port()
    with TrapListener(port=port, bind_host="127.0.0.1") as listener:
        trap = listener.wait_for(timeout=1)
    assert trap is None


def test_wait_for_receives_a_datagram() -> None:
    port = _free_port()
    payload = b"\x30\x03\x02\x01\x00"  # minimal BER SEQUENCE { INTEGER 0 }
    with TrapListener(port=port, bind_host="127.0.0.1") as listener:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(payload, ("127.0.0.1", port))
        trap = listener.wait_for(timeout=5)

    assert trap is not None
    assert trap.source_ip == "127.0.0.1"
    assert trap.payload == payload


def test_wait_for_ignores_datagrams_from_an_unexpected_source() -> None:
    """A source filter that never matches must not return the first thing
    that arrives -- it has to keep waiting (and eventually time out), the
    same way it would drain unrelated LAN traffic while watching for one
    specific device's trap."""
    port = _free_port()
    with TrapListener(port=port, bind_host="127.0.0.1") as listener:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"\x30\x00", ("127.0.0.1", port))
        trap = listener.wait_for(timeout=1, expected_source="10.0.0.99")

    assert trap is None


def test_wait_for_matches_the_expected_source() -> None:
    port = _free_port()
    with TrapListener(port=port, bind_host="127.0.0.1") as listener:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"\x30\x00", ("127.0.0.1", port))
        trap = listener.wait_for(timeout=5, expected_source="127.0.0.1")

    assert trap is not None
    assert trap.source_ip == "127.0.0.1"


def test_double_bind_raises_a_clear_error() -> None:
    """A real SNMP trap daemon already running on the test PC would collide
    exactly like this -- the error should say so rather than leaving a bare
    OSError for the reader to decode."""
    port = _free_port()
    with TrapListener(port=port, bind_host="127.0.0.1"):
        with pytest.raises(ValidationExecutionError, match="already listening"):
            with TrapListener(port=port, bind_host="127.0.0.1"):
                pass


def test_wait_for_outside_the_with_block_raises() -> None:
    listener = TrapListener(port=_free_port(), bind_host="127.0.0.1")
    with pytest.raises(ValidationExecutionError, match="with"):
        listener.wait_for(timeout=1)


def test_non_ber_payload_is_received_but_not_decoded() -> None:
    """A datagram that doesn't even start with BER's SEQUENCE tag is still
    real evidence of receipt -- the primary proof this validation exists
    for -- it just can't be read further, and should say so by leaving
    version/username unset rather than guessing."""
    trap = _parse("192.0.2.1", b"not-snmp-at-all")
    assert trap.source_ip == "192.0.2.1"
    assert trap.version is None
    assert trap.username is None


def test_decode_header_reads_v3_username() -> None:
    """Full round trip: build a real SNMPv3 message with pyasn1 (the same
    encoder pysnmp itself uses) and confirm the header-only decode recovers
    msgVersion and msgUserName without needing the auth/privacy keys --
    exactly the property that makes this safe to do without decrypting
    authPriv traffic.
    """
    pyasn1_codec = pytest.importorskip("pyasn1.codec.ber.encoder")
    from pyasn1.type import univ

    from switchtest.infrastructure.trap_listener import _decode_header

    usm_security_params = univ.Sequence()
    usm_security_params.setComponentByPosition(0, univ.OctetString(hexValue="00"))  # engineID
    usm_security_params.setComponentByPosition(1, univ.Integer(0))  # engineBoots
    usm_security_params.setComponentByPosition(2, univ.Integer(0))  # engineTime
    usm_security_params.setComponentByPosition(3, univ.OctetString("snmpv3"))  # msgUserName
    usm_security_params.setComponentByPosition(4, univ.OctetString(""))  # authParams
    usm_security_params.setComponentByPosition(5, univ.OctetString(""))  # privParams
    encoded_security_params = pyasn1_codec.encode(usm_security_params)

    message = univ.Sequence()
    message.setComponentByPosition(0, univ.Integer(3))  # msgVersion = SNMPv3
    message.setComponentByPosition(1, univ.OctetString("global-data-placeholder"))
    message.setComponentByPosition(2, univ.OctetString(encoded_security_params))
    message.setComponentByPosition(3, univ.OctetString("msg-data-placeholder"))
    payload = pyasn1_codec.encode(message)

    version, username = _decode_header(payload)

    assert version == "v3"
    assert username == "snmpv3"
