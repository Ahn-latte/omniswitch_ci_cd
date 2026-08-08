import pytest

from switchtest.domain.enums import ResultStatus, ValidationType
from switchtest.domain.testcase import SnmpCredentials, ValidationStep
from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure import snmp as snmp_module
from switchtest.infrastructure.reporting.progress import SnmpTranscriptRenderer
from switchtest.infrastructure.snmp import (
    SnmpResult,
    SnmpV3Params,
    observing,
    snmp_get,
    snmp_set,
)
from switchtest.services import validation_service as validation_module
from switchtest.services.validation_service import ValidationService

PARAMS = SnmpV3Params(user="snmpv3", auth_password="12#qweASD", priv_password="12#qweASD")


def _rendered(binding):
    """A pysnmp binding only knows its own name once it has been resolved
    against a MIB, which normally happens inside the request these tests stub
    out. Resolving it here is what lets them assert on the OID."""
    from pysnmp.smi import builder, view

    binding.resolve_with_mib(view.MibViewController(builder.MibBuilder()))
    return [str(part) for part in binding]


@pytest.fixture()
def captured_request(monkeypatch):
    """Answer each request with a scripted result and record what was asked.

    Stops at the async boundary: everything above it -- credential building,
    OID translation, value typing, observer notification -- is what these
    tests are about, and stubbing there keeps them off the network.
    """
    calls: list[dict] = []
    replies: list[SnmpResult] = []

    async def fake_execute(operation, target, port, params, binding, timeout):
        calls.append(
            {
                "operation": operation,
                "target": target,
                "port": port,
                "params": params,
                "binding": binding,
                "timeout": timeout,
            }
        )
        return replies.pop(0) if replies else SnmpResult(True, "OS6900", "raw")

    monkeypatch.setattr(snmp_module, "_execute", fake_execute)
    return calls, replies


def test_snmp_get_resolves_a_bare_oid_against_snmpv2_mib(captured_request) -> None:
    calls, _ = captured_request

    result = snmp_get("192.168.1.1", 161, "sysName.0", PARAMS, timeout=20)

    assert result.ok
    assert result.value == "OS6900"
    assert calls[0]["operation"] == "GET"
    assert calls[0]["timeout"] == 20
    # All spellings resolve to the object's real OID; sysName.0 is 1.3.6.1.2.1.1.5.0.
    assert _rendered(calls[0]["binding"])[0] == "1.3.6.1.2.1.1.5.0"


@pytest.mark.parametrize(
    "oid, expected",
    [
        ("sysName.0", "1.3.6.1.2.1.1.5.0"),
        ("SNMPv2-MIB::sysDescr.0", "1.3.6.1.2.1.1.1.0"),
        ("1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.5.0"),
        (".1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.5.0"),
    ],
)
def test_every_accepted_oid_spelling_reaches_pysnmp(captured_request, oid, expected) -> None:
    calls, _ = captured_request

    snmp_get("192.168.1.1", 161, oid, PARAMS)

    assert _rendered(calls[0]["binding"])[0] == expected


def test_snmp_set_carries_the_typed_value(captured_request) -> None:
    calls, _ = captured_request

    snmp_set("192.168.1.1", 161, "sysName.0", "OS6900-SNMPTEST", PARAMS)

    name, value = _rendered(calls[0]["binding"])
    assert calls[0]["operation"] == "SET"
    assert name == "1.3.6.1.2.1.1.5.0"
    assert value == "OS6900-SNMPTEST"


def test_an_unknown_value_type_is_rejected_before_any_request(captured_request) -> None:
    calls, _ = captured_request

    with pytest.raises(ValidationExecutionError, match="value type"):
        snmp_set("192.168.1.1", 161, "sysName.0", "1", PARAMS, value_type="z")

    assert calls == []


def test_an_unknown_auth_protocol_is_rejected() -> None:
    params = SnmpV3Params(user="u", auth_password="p", priv_password="p", auth_protocol="SHA-999")

    with pytest.raises(ValidationExecutionError, match="auth protocol"):
        snmp_module._user_data(params)


@pytest.mark.parametrize("spelling", ["SHA-256", "sha256", "SHA 256"])
def test_protocol_names_are_matched_regardless_of_punctuation(spelling) -> None:
    params = SnmpV3Params(user="u", auth_password="p", priv_password="p", auth_protocol=spelling)

    assert snmp_module._user_data(params) is not None


def test_auth_no_priv_supplies_no_privacy_key() -> None:
    params = SnmpV3Params(user="u", auth_password="p", priv_password="p", level="authNoPriv")

    user_data = snmp_module._user_data(params)

    assert user_data.privacy_protocol == snmp_module.usmNoPrivProtocol
    assert user_data.authentication_protocol == snmp_module.usmHMAC192SHA256AuthProtocol


def test_agent_refusal_is_reported_as_denied(captured_request) -> None:
    _, replies = captured_request
    replies.append(SnmpResult(False, None, "notWritable at SNMPv2-MIB::sysName.0", refused=True))

    result = snmp_set("192.168.1.1", 161, "sysName.0", "x", PARAMS)

    assert not result.ok
    assert result.denied
    assert not result.unanswered


def test_a_usm_rejection_counts_as_an_answer(captured_request) -> None:
    """A wrong password is the agent saying no, not the agent staying silent --
    snmp_denied treats the two differently."""
    _, replies = captured_request
    replies.append(SnmpResult(False, None, "Wrong SNMP PDU digest"))

    result = snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)

    assert result.denied
    assert not result.unanswered


def test_no_response_is_distinguished_from_a_refusal(captured_request) -> None:
    _, replies = captured_request
    replies.append(SnmpResult(False, None, "No SNMP response received before timeout"))

    result = snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)

    assert result.unanswered
    assert not result.denied


def test_passwords_never_reach_the_result(captured_request) -> None:
    _, replies = captured_request
    replies.append(SnmpResult(False, None, "rejected credentials 12#qweASD"))

    result = snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)

    assert "12#qweASD" not in result.detail
    assert "******" in result.detail


# -- console transcript ----------------------------------------------------


def test_the_transcript_shows_each_request_and_its_answer(captured_request) -> None:
    _, replies = captured_request
    replies.append(SnmpResult(True, "OS6900", "raw"))
    replies.append(SnmpResult(False, None, "notWritable", refused=True))
    lines: list[str] = []

    with observing(SnmpTranscriptRenderer(echo=lines.append).handle):
        snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)
        snmp_set("192.168.1.1", 161, "sysName.0", "OS6900-DENIED", PARAMS)

    # One header for the account, then a line per exchange.
    assert lines[0] == "  snmp: v3 authPriv SHA-256/AES as 'snmpv3' -> 192.168.1.1:161"
    assert "GET sysName.0" in lines[1] and "OS6900" in lines[1]
    assert "SET sysName.0 = OS6900-DENIED" in lines[2] and "refused: notWritable" in lines[2]
    assert all("12#qweASD" not in line for line in lines)


def test_the_transcript_reprints_the_header_when_the_account_changes(captured_request) -> None:
    read_only = SnmpV3Params(user="snmpv3ro", auth_password="p", priv_password="p")
    lines: list[str] = []

    with observing(SnmpTranscriptRenderer(echo=lines.append).handle):
        snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)
        snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)
        snmp_get("192.168.1.1", 161, "sysName.0", read_only)

    headers = [line for line in lines if line.startswith("  snmp:")]
    assert len(headers) == 2
    assert "snmpv3ro" in headers[1]


def test_nothing_is_printed_without_an_observer(captured_request) -> None:
    with observing(None):
        result = snmp_get("192.168.1.1", 161, "sysName.0", PARAMS)

    assert result.ok


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
