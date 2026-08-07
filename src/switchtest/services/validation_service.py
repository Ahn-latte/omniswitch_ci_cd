import os
import re

from switchtest.domain.enums import ResultStatus, ValidationType
from switchtest.domain.results import ValidationResult
from switchtest.domain.testcase import ValidationStep
from switchtest.drivers.base import BaseSwitchDriver
from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.api_probe import check_api_unreachable
from switchtest.infrastructure.nmap import scan_port, scan_top_ports
from switchtest.infrastructure.ping import ping_target
from switchtest.infrastructure.secrets import get_required_secret
from switchtest.infrastructure.snmp import SnmpResult, SnmpV3Params, redact, snmp_get, snmp_set
from switchtest.infrastructure.tcp_probe import probe_tcp
from switchtest.infrastructure.tls_capture import capture_tls_version
from switchtest.infrastructure.web_probe import check_web_unreachable
from switchtest.utils.text import normalize_cli_output


class ValidationService:
    def run_validation(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        handlers = {
            ValidationType.CONTAINS: self._validate_contains,
            ValidationType.NOT_CONTAINS: self._validate_not_contains,
            ValidationType.REGEX: self._validate_regex,
            ValidationType.EQUALS: self._validate_equals,
            ValidationType.PING: self._validate_ping,
            ValidationType.PORT_CLOSED: self._validate_port_closed,
            ValidationType.PORT_SCAN_CLOSED: self._validate_port_scan_closed,
            ValidationType.WEB_UNREACHABLE: self._validate_web_unreachable,
            ValidationType.API_UNREACHABLE: self._validate_api_unreachable,
            ValidationType.TLS_VERSION: self._validate_tls_version,
            ValidationType.TCP_BLOCKED: self._validate_tcp_blocked,
            ValidationType.SNMP_GET: self._validate_snmp_get,
            ValidationType.SNMP_SET: self._validate_snmp_set,
            ValidationType.SNMP_DENIED: self._validate_snmp_denied,
        }
        handler = handlers[validation.type]
        return handler(driver, validation)

    def _validate_contains(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        output = self._run_show(driver, validation)
        expected = validation.expected or ""
        matched = expected in output
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if matched else ResultStatus.FAIL,
            observed=output,
            expected=expected,
            message=None if matched else f"Expected '{expected}' to appear",
        )

    def _validate_not_contains(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        output = self._run_show(driver, validation)
        expected = validation.expected or ""
        matched = expected not in output
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if matched else ResultStatus.FAIL,
            observed=output,
            expected=expected,
            message=None if matched else f"Did not expect '{expected}' to appear",
        )

    def _validate_regex(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        output = self._run_show(driver, validation)
        pattern = validation.pattern or ""
        matched = re.search(pattern, output, re.MULTILINE) is not None
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if matched else ResultStatus.FAIL,
            observed=output,
            expected=pattern,
            message=None if matched else f"Regex '{pattern}' did not match",
        )

    def _validate_equals(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        output = normalize_cli_output(self._run_show(driver, validation))
        expected = normalize_cli_output(validation.expected or "")
        matched = output == expected
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if matched else ResultStatus.FAIL,
            observed=output,
            expected=expected,
            message=None if matched else "Observed output did not equal expected output",
        )

    def _validate_ping(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        success, output = ping_target(validation.target or "", timeout=validation.timeout)
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if success else ResultStatus.FAIL,
            observed=output,
            expected=validation.target,
            message=None if success else f"Ping to {validation.target} failed",
        )

    def _validate_port_closed(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        protocol = validation.protocol.value
        state, output = scan_port(
            validation.target or "",
            validation.port or 0,
            timeout=validation.timeout,
            protocol=protocol,
        )
        closed = state != "open"
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if closed else ResultStatus.FAIL,
            observed=output,
            expected=f"{protocol} port {validation.port} not open",
            message=None
            if closed
            else f"Port {validation.port}/{protocol} on {validation.target} is open "
            f"(expected closed/filtered)",
        )

    def _validate_port_scan_closed(
        self, driver: BaseSwitchDriver, validation: ValidationStep
    ) -> ValidationResult:
        """One scan across the most common TCP and UDP ports; passes when none
        of them is open. Any port that is open is named in the message, so a
        failure says which service is still listening."""
        open_ports, summary = scan_top_ports(
            validation.target or "",
            top_ports=validation.top_ports,
            timeout=validation.timeout,
        )
        scope = f"top {validation.top_ports} tcp and udp ports on {validation.target}"
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if not open_ports else ResultStatus.FAIL,
            observed=summary,
            expected=f"no open ports among the {scope}",
            message=None if not open_ports else f"Still open: {', '.join(open_ports)}",
        )

    def _validate_web_unreachable(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        unreachable, output = check_web_unreachable(
            validation.target or "", validation.port or 0, timeout=validation.timeout
        )
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if unreachable else ResultStatus.FAIL,
            observed=output,
            expected=f"http(s) on port {validation.port} unreachable",
            message=None
            if unreachable
            else f"Web service on {validation.target}:{validation.port} is still reachable",
        )

    def _validate_api_unreachable(
        self, driver: BaseSwitchDriver, validation: ValidationStep
    ) -> ValidationResult:
        unreachable, detail = check_api_unreachable(
            validation.target or "",
            validation.port or 0,
            path=validation.path,
            timeout=validation.timeout,
        )
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if unreachable else ResultStatus.FAIL,
            observed=detail,
            expected=f"JSON API on {validation.target}:{validation.port} unreachable",
            message=None
            if unreachable
            else f"The API on {validation.target}:{validation.port} still answers requests",
        )

    def _validate_tls_version(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        interface = os.environ.get("SWITCHTEST_CAPTURE_INTERFACE", "")
        version_name, raw_hex, pcap_path = capture_tls_version(
            interface, validation.target or "", validation.port or 0, duration=validation.timeout
        )
        expected = validation.expected or "TLS 1.2"
        observed = f"{version_name} ({raw_hex}) -- capture saved at {pcap_path}"
        matched = version_name == expected
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if matched else ResultStatus.FAIL,
            observed=observed,
            expected=expected,
            message=None if matched else f"Expected {expected}, observed {version_name} ({raw_hex})",
        )

    def _validate_tcp_blocked(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        blocked, detail = probe_tcp(validation.target or "", validation.port or 0, timeout=validation.timeout)
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if blocked else ResultStatus.FAIL,
            observed=detail,
            expected=f"tcp/{validation.port} on {validation.target} unreachable from this host",
            message=None if blocked else f"Expected the connection to be blocked, but {detail}",
        )

    def _validate_snmp_get(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        params = _snmp_params(validation)
        result = snmp_get(
            validation.target or "",
            validation.port or 161,
            _require_oid(validation),
            params,
            timeout=validation.timeout,
        )
        expected = validation.expected or validation.pattern or "any value"
        if not result.ok:
            return ValidationResult(
                name=validation.name,
                status=ResultStatus.FAIL,
                observed=redact(params, result.detail),
                expected=expected,
                message=f"SNMP GET of {validation.oid} failed as user '{params.user}'",
            )
        matched = _value_matches(result.value or "", validation)
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if matched else ResultStatus.FAIL,
            observed=result.value,
            expected=expected,
            message=None if matched else f"SNMP GET returned '{result.value}'",
        )

    def _validate_snmp_set(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        """Write a value, confirm it took, then put the original back.

        Restoring here rather than in the testcase's cleanup keeps the object
        under test (sysName, in practice) modified for the shortest possible
        window, and means the testcase doesn't have to hardcode the value the
        device happened to have.
        """
        params = _snmp_params(validation)
        target = validation.target or ""
        port = validation.port or 161
        oid = _require_oid(validation)
        new_value = validation.value
        if new_value is None:
            raise ValidationExecutionError(f"Validation '{validation.name}' requires a value to set")

        original = snmp_get(target, port, oid, params, timeout=validation.timeout)
        if not original.ok:
            return ValidationResult(
                name=validation.name,
                status=ResultStatus.FAIL,
                observed=redact(params, original.detail),
                expected=new_value,
                message=f"Could not read {oid} before setting it (as user '{params.user}')",
            )

        written = snmp_set(
            target, port, oid, new_value, params, value_type=validation.value_type, timeout=validation.timeout
        )
        try:
            if not written.ok:
                return ValidationResult(
                    name=validation.name,
                    status=ResultStatus.FAIL,
                    observed=redact(params, written.detail),
                    expected=new_value,
                    message=f"SNMP SET of {oid} was rejected for user '{params.user}'",
                )
            readback = snmp_get(target, port, oid, params, timeout=validation.timeout)
            matched = readback.ok and (readback.value or "") == new_value
            return ValidationResult(
                name=validation.name,
                status=ResultStatus.PASS if matched else ResultStatus.FAIL,
                observed=readback.value if readback.ok else redact(params, readback.detail),
                expected=new_value,
                message=None if matched else f"{oid} did not read back as '{new_value}' after the SET",
            )
        finally:
            _restore_snmp_value(target, port, oid, original.value or "", params, validation)

    def _validate_snmp_denied(self, driver: BaseSwitchDriver, validation: ValidationStep) -> ValidationResult:
        """Assert the agent refuses this account -- a SET with a read-only user,
        or a GET with one that has no access at all.

        A refusal (`notWritable`, `noAccess`, USM authentication failure) is
        the expected outcome. No answer at all also counts as "not permitted",
        but is reported as such: it can equally mean SNMP is switched off or a
        firewall ate the request, which is a different finding.
        """
        params = _snmp_params(validation)
        target = validation.target or ""
        port = validation.port or 161
        oid = _require_oid(validation)

        if validation.value is None:
            result = snmp_get(target, port, oid, params, timeout=validation.timeout)
            if not result.ok:
                return _denied_result(validation, params, result)
            return ValidationResult(
                name=validation.name,
                status=ResultStatus.FAIL,
                observed=result.value,
                expected=f"{oid} not readable by '{params.user}'",
                message=f"SNMP GET unexpectedly succeeded for user '{params.user}'",
            )

        # A read-only account must not be able to write. If it somehow does,
        # the value has to go back before this reports the failure.
        original = snmp_get(target, port, oid, params, timeout=validation.timeout)
        result = snmp_set(
            target,
            port,
            oid,
            validation.value,
            params,
            value_type=validation.value_type,
            timeout=validation.timeout,
        )
        if not result.ok:
            return _denied_result(validation, params, result)
        if original.ok:
            _restore_snmp_value(target, port, oid, original.value or "", params, validation)
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.FAIL,
            observed=redact(params, result.detail),
            expected=f"{oid} not writable by '{params.user}'",
            message=f"SNMP SET unexpectedly succeeded for read-only user '{params.user}'",
        )

    def _run_show(self, driver: BaseSwitchDriver, validation: ValidationStep) -> str:
        if not validation.command:
            raise ValidationExecutionError(f"Validation '{validation.name}' requires a command")
        return driver.run_show(validation.command, timeout=validation.timeout, reauth=validation.reauth)


def _snmp_params(validation: ValidationStep) -> SnmpV3Params:
    credentials = validation.snmp
    if credentials is None:
        raise ValidationExecutionError(
            f"Validation '{validation.name}' requires an 'snmp' block (user and passwords)"
        )
    auth_password = _resolve_secret(
        credentials.auth_password, credentials.auth_password_env, validation.name, "auth"
    )
    # An AOS SNMPv3 account created as `sha256+aes` uses its one password for
    # both, so the privacy password falls back to the auth password.
    priv_password = auth_password
    if credentials.priv_password or credentials.priv_password_env:
        priv_password = _resolve_secret(
            credentials.priv_password, credentials.priv_password_env, validation.name, "privacy"
        )
    return SnmpV3Params(
        user=credentials.user,
        auth_password=auth_password,
        priv_password=priv_password,
        level=credentials.level,
        auth_protocol=credentials.auth_protocol,
        priv_protocol=credentials.priv_protocol,
    )


def _resolve_secret(
    inline: str | None, env_name: str | None, validation_name: str, kind: str
) -> str:
    if env_name:
        return get_required_secret(env_name)
    if inline:
        return inline
    raise ValidationExecutionError(
        f"Validation '{validation_name}' needs an SNMP {kind} password "
        f"({kind}_password or {kind}_password_env)"
    )


def _require_oid(validation: ValidationStep) -> str:
    if not validation.oid:
        raise ValidationExecutionError(f"Validation '{validation.name}' requires an oid")
    return validation.oid


def _value_matches(value: str, validation: ValidationStep) -> bool:
    if validation.expected is not None:
        return value == validation.expected
    if validation.pattern:
        return re.search(validation.pattern, value) is not None
    return bool(value)


def _denied_result(
    validation: ValidationStep, params: SnmpV3Params, result: SnmpResult
) -> ValidationResult:
    detail = redact(params, result.detail)
    if result.unanswered:
        message = (
            "Refused as expected, but the agent never answered -- that also happens when SNMP "
            "is disabled or the request is filtered, so this is weaker evidence than an "
            "explicit refusal"
        )
    else:
        message = None
    return ValidationResult(
        name=validation.name,
        status=ResultStatus.PASS,
        observed=detail,
        expected=f"refused for user '{params.user}'",
        message=message,
    )


def _restore_snmp_value(
    target: str,
    port: int,
    oid: str,
    original: str,
    params: SnmpV3Params,
    validation: ValidationStep,
) -> None:
    restored = snmp_set(
        target, port, oid, original, params, value_type=validation.value_type, timeout=validation.timeout
    )
    if not restored.ok:
        raise ValidationExecutionError(
            f"Could not restore {oid} to '{original}' after '{validation.name}': "
            f"{redact(params, restored.detail)}"
        )
