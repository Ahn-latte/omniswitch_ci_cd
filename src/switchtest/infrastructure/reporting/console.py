from collections import Counter

from switchtest.domain.enums import ResultStatus
from switchtest.domain.results import SuiteResult


def render_suite_summary(result: SuiteResult) -> str:
    counts = Counter(test.status.value for test in result.tests)
    lines = [
        f"Suite: {result.suite_name}",
        f"Device: {result.device_name}",
        f"Platform: {result.platform}",
        f"Firmware: {result.firmware_version or 'unknown'}",
        f"Model: {result.device_model or 'unknown'}",
        f"Status: {result.status.value}",
        f"Pass: {counts.get(ResultStatus.PASS.value, 0)} "
        f"Fail: {counts.get(ResultStatus.FAIL.value, 0)} "
        f"Error: {counts.get(ResultStatus.ERROR.value, 0)} "
        f"Skipped: {counts.get(ResultStatus.SKIPPED.value, 0)}",
        "",
        "Tests:",
    ]
    for test in result.tests:
        lines.append(f"  [{test.status.value.upper()}] {test.test_id} {test.test_name}")
        if test.status in (ResultStatus.FAIL, ResultStatus.ERROR):
            if test.error_message:
                lines.append(f"    error: {test.error_message}")
            for validation in test.validation_results:
                if validation.status in (ResultStatus.FAIL, ResultStatus.ERROR):
                    lines.append(
                        f"    - {validation.name}: expected={validation.expected!r} "
                        f"observed={validation.observed!r} ({validation.message or 'no message'})"
                    )
    return "\n".join(lines)
