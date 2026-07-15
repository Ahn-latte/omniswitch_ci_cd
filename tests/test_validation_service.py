from switchtest.domain.enums import ResultStatus, ValidationType
from switchtest.domain.testcase import ValidationStep
from switchtest.services.validation_service import ValidationService


class StubDriver:
    def run_show(self, command: str, timeout: int = 30, reauth: bool = False) -> str:
        if command == "show vlan":
            return "VLAN 100 CI_TEST_VLAN100"
        return "Version 1.0"


def test_contains_validator_passes() -> None:
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(
            name="contains",
            type=ValidationType.CONTAINS,
            command="show vlan",
            expected="CI_TEST_VLAN100",
        ),
    )
    assert result.status == ResultStatus.PASS


def test_equals_validator_fails() -> None:
    service = ValidationService()
    result = service.run_validation(
        StubDriver(),
        ValidationStep(
            name="equals",
            type=ValidationType.EQUALS,
            command="show version",
            expected="Different",
        ),
    )
    assert result.status == ResultStatus.FAIL
