from switchtest.domain.device import DeviceDefinition
from switchtest.domain.enums import TransportType
from switchtest.drivers.aos import AOSSwitchDriver, _extract_firmware, _extract_model
from switchtest.exceptions import ConnectionError as SwitchConnectionError
from switchtest.infrastructure.console.client import SerialConsoleTransport
from switchtest.infrastructure.ssh.client import SSHTransport


SHOW_SYSTEM_OUTPUT = """ACSW01-> show system

  Description:  Alcatel-Lucent Enterprise OS6860E-P24 8.9.221.R03 GA, October 12, 2023.,
  Object ID:    1.3.6.1.4.1.6486.801.1.1.2.1.11.1.6,
  Up Time:      12 days 4 hours 24 minutes and 21 seconds,
  Contact:      jerry.poh@al-enterprise.com,
  Name:         ACSW01,
  Location:     ALE Demo Lab,
  Services:     78,
  Date & Time:  SUN MAR 29 2026 15:43:07 (ZP8)
"""


def test_extract_model_from_show_system() -> None:
    assert _extract_model(SHOW_SYSTEM_OUTPUT) == "OS6860E-P24"


def test_extract_firmware_from_show_system() -> None:
    assert _extract_firmware(SHOW_SYSTEM_OUTPUT) == "8.9.221.R03 GA"


def _device(**overrides) -> DeviceDefinition:
    defaults = dict(
        name="dev",
        host="192.168.1.1",
        username="secureadmin",
        password_env="SWITCH_TEST_PASSWORD",
        platform="aos",
        expected_prompt="->",
    )
    defaults.update(overrides)
    return DeviceDefinition(**defaults)


def test_driver_uses_ssh_transport_by_default(monkeypatch) -> None:
    monkeypatch.setenv("SWITCH_TEST_PASSWORD", "secret")
    transport = AOSSwitchDriver(_device())._build_transport()
    assert isinstance(transport, SSHTransport)


def test_driver_uses_serial_transport_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("SWITCH_TEST_PASSWORD", "secret")
    device = _device(transport=TransportType.SERIAL, serial_port="COM9", serial_baudrate=115200)

    transport = AOSSwitchDriver(device)._build_transport()

    assert isinstance(transport, SerialConsoleTransport)
    assert transport.serial_port == "COM9"
    assert transport.baudrate == 115200
    assert transport.prompt == "->"


def test_failed_login_attempts_stay_on_ssh_for_serial_devices(monkeypatch) -> None:
    # The IP ban under test is triggered by network logins; a console attempt
    # would never register against this machine's IP.
    monkeypatch.setenv("SWITCH_TEST_PASSWORD", "secret")
    device = _device(transport=TransportType.SERIAL, serial_port="COM9")
    built: list[SSHTransport] = []

    class RecordingTransport(SSHTransport):
        def connect(self) -> None:
            built.append(self)
            raise SwitchConnectionError("rejected")

        def close(self) -> None:
            return None

    monkeypatch.setattr("switchtest.drivers.aos.SSHTransport", RecordingTransport)

    assert AOSSwitchDriver(device).attempt_login("admin1", "wrong") is False
    assert built[0].host == "192.168.1.1"
    assert built[0].port == 22
