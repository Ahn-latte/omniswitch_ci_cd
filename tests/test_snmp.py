import subprocess

import pytest

from switchtest.domain.enums import ResultStatus, ValidationType
from switchtest.domain.testcase import SnmpCredentials, ValidationStep
from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure import snmp as snmp_module
from switchtest.infrastructure.snmp import SnmpResult, SnmpV3Params, snmp_get, snmp_set
from switchtest.services import validation_service as validation_module
from switchtest.services.validation_service import ValidationService

PARAMS = SnmpV3Params(user="snmpv3", auth_password="12#qweASD", priv_password="12#qweASD")


class FakeCompleted:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture()
def captured_run(monkeypatch):
    """Capture the net-snmp command line and reply with a scripted result."""

    calls: list[list[str]] = []
    replies: list[FakeCompleted] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return replies.pop(0) if replies else FakeCompleted()

    monkeypatch.setattr(snmp_module.subprocess, "run", fake_run)
    return calls, replies


def test_snmp_get_builds_v3_authpriv_arguments(captured_run) -> None:
    calls, replies = captured_run
    replies.append(FakeCompleted(stdout="SNMPv2-MIB::sysName.0 = STRING: OS6900\n"))

    result = snmp_get("192.168.1.1", 161, "sysName.0", PARAMS, timeout=20)

    assert result.ok
    assert result.value == "OS6900"
    assert calls[0] == [
        "snmpget",
        "-v3",
        "-l",
        "authPriv",
        "-u",
        "snmpv3",
        "-a",
        "SHA-256",
        "-A",
        "12#qweASD",
        "-x",
        "AES",
        "-X",
        "12#qweASD",
        "-t",
        "20",
        "-r",
        "0",
        "192.168.1.1:161",
        "sysName.0",
    ]


def test_snmp_set_passes_type_and_value(captured_run) -> None:
    calls, replies = captured_run
    replies.append(FakeCompleted(stdout="SNMPv2-MIB::sysName.0 = STRING: OS6900-SNMPTEST\n"))

    result = snmp_set("192.168.1.1", 161, "sysName.0", "OS6900-SNMPTEST", PARAMS)

    assert result.ok
    assert calls[0][:1] == ["snmpset"]
    assert calls[0][-3:] == ["sysName.0", "s", "OS6900-SNMPTEST"]


def test_auth_no_priv_omits_privacy_arguments(captured_run) -> None:
    calls, replies = captured_run
    replies.append(FakeCompleted(stdout="SNMPv2-MIB::sysName.0 = STRING: OS6900\n"))

    snmp_get("192.168.1.1", 161, "sysName.0", SnmpV3Params(
        user="u", auth_password="p", priv_password="p", level="authNoPriv"
    ))

    assert "-x" not in calls[0]
    assert "-A" in calls[0]


def test_agent_refusal_is_reported_as_denied(captured_run) -> None:
    _, replies = captured_run
    replies.append(
        FakeCompleted(returncode=2, stderr="Error in packet.\nReason: notWritable\n")
    )

    result = snmp_set("192.168.1.1", 161, "sysName.0", "x", PARAMS)

    assert not result.ok
    assert result.denied
    assert not result.unanswered


def test_no_response_is_distinguished_from_a_refusal(captured_run) -> None:
    _, replies = captured_run
    replies.append(FakeCompleted(returncode=1, stderr="Timeout: No Response from 192.168.1.1:161"))

    result = snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)

    assert result.unanswered
    assert not result.denied


def test_missing_net_snmp_is_an_actionable_error(monkeypatch) -> None:
    def missing(command, **kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(snmp_module.subprocess, "run", missing)

    with pytest.raises(ValidationExecutionError, match="net-snmp"):
        snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)


def test_subprocess_timeout_becomes_a_no_response_result(monkeypatch) -> None:
    def slow(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 30)

    monkeypatch.setattr(snmp_module.subprocess, "run", slow)

    result = snmp_get("192.168.1.1", 161, "sysName.0", PARAMS, timeout=20)

    assert result.unanswered


# -- validation service ----------------------------------------------------


def _validation(**overrides) -> ValidationStep:
    defaults = dict(
        name="snmp check",
        type=ValidationType.SNMP_GET,
        target="192.168.1.1",
        port=161,
        oid="sysName.0",
        snmp=SnmpCredentials(user="snmpv3", auth_password="12#qweASD"),
    )
    defaults.update(overrides)
    return ValidationStep(**defaults)


def test_snmp_get_validation_compares_the_value(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_module, "snmp_get", lambda *a, **k: SnmpResult(True, "OS6900", "raw")
    )

    result = ValidationService().run_validation(None, _validation(expected="OS6900"))

    assert result.status == ResultStatus.PASS


def test_snmp_set_validation_restores_the_original_value(monkeypatch) -> None:
    values = {"sysName.0": "OS6900"}
    sets: list[str] = []

    def fake_get(*args, **kwargs):
        return SnmpResult(True, values["sysName.0"], "raw")

    def fake_set(target, port, oid, value, params, value_type="s", timeout=30):
        sets.append(value)
        values[oid] = value
        return SnmpResult(True, value, "raw")

    monkeypatch.setattr(validation_module, "snmp_get", fake_get)
    monkeypatch.setattr(validation_module, "snmp_set", fake_set)

    result = ValidationService().run_validation(
        None, _validation(type=ValidationType.SNMP_SET, value="OS6900-SNMPTEST")
    )

    assert result.status == ResultStatus.PASS
    assert sets == ["OS6900-SNMPTEST", "OS6900"]
    assert values["sysName.0"] == "OS6900"


def test_snmp_denied_passes_when_the_agent_refuses(monkeypatch) -> None:
    monkeypatch.setattr(
        validation_module, "snmp_get", lambda *a, **k: SnmpResult(True, "OS6900", "raw")
    )
    monkeypatch.setattr(
        validation_module,
        "snmp_set",
        lambda *a, **k: SnmpResult(False, None, "Error in packet.\nReason: notWritable"),
    )

    result = ValidationService().run_validation(
        None, _validation(type=ValidationType.SNMP_DENIED, value="OS6900-DENIED")
    )

    assert result.status == ResultStatus.PASS


def test_snmp_denied_fails_and_restores_when_the_write_succeeds(monkeypatch) -> None:
    sets: list[str] = []
    monkeypatch.setattr(
        validation_module, "snmp_get", lambda *a, **k: SnmpResult(True, "OS6900", "raw")
    )

    def fake_set(target, port, oid, value, params, value_type="s", timeout=30):
        sets.append(value)
        return SnmpResult(True, value, "raw")

    monkeypatch.setattr(validation_module, "snmp_set", fake_set)

    result = ValidationService().run_validation(
        None, _validation(type=ValidationType.SNMP_DENIED, value="OS6900-DENIED")
    )

    # A read-only account that can write is a finding -- and the value it wrote
    # must not be left on the device.
    assert result.status == ResultStatus.FAIL
    assert sets == ["OS6900-DENIED", "OS6900"]


def test_snmp_validation_requires_credentials() -> None:
    with pytest.raises(ValidationExecutionError, match="snmp"):
        ValidationService().run_validation(None, _validation(snmp=None))


def test_snmp_password_can_come_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("SWITCH_SNMP_TEST_PASSWORD", "from-env")
    captured: dict[str, SnmpV3Params] = {}

    def fake_get(target, port, oid, params, timeout=30):
        captured["params"] = params
        return SnmpResult(True, "OS6900", "raw")

    monkeypatch.setattr(validation_module, "snmp_get", fake_get)

    ValidationService().run_validation(
        None,
        _validation(
            snmp=SnmpCredentials(user="snmpv3", auth_password_env="SWITCH_SNMP_TEST_PASSWORD")
        ),
    )

    assert captured["params"].auth_password == "from-env"
    # sha256+aes accounts share one password, so privacy falls back to it.
    assert captured["params"].priv_password == "from-env"
