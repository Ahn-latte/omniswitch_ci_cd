import os
import re

from switchtest.domain.enums import ResultStatus, ValidationType
from switchtest.domain.results import ValidationResult
from switchtest.domain.testcase import ValidationStep
from switchtest.drivers.base import BaseSwitchDriver
from switchtest.exceptions import ValidationExecutionError
from switchtest.infrastructure.nmap import scan_port
from switchtest.infrastructure.ping import ping_target
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
            ValidationType.WEB_UNREACHABLE: self._validate_web_unreachable,
            ValidationType.TLS_VERSION: self._validate_tls_version,
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
        state, output = scan_port(validation.target or "", validation.port or 0, timeout=validation.timeout)
        closed = state != "open"
        return ValidationResult(
            name=validation.name,
            status=ResultStatus.PASS if closed else ResultStatus.FAIL,
            observed=output,
            expected=f"port {validation.port} not open",
            message=None
            if closed
            else f"Port {validation.port} on {validation.target} is open (expected closed/filtered)",
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

    def _run_show(self, driver: BaseSwitchDriver, validation: ValidationStep) -> str:
        if not validation.command:
            raise ValidationExecutionError(f"Validation '{validation.name}' requires a command")
        return driver.run_show(validation.command, timeout=validation.timeout, reauth=validation.reauth)
