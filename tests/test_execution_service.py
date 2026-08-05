from switchtest.domain.enums import ResultStatus, TestAction
from switchtest.domain.runtime import RuntimeContext
from switchtest.domain.testcase import TestCaseDefinition, TestStep
from switchtest.services.execution_service import ExecutionService
from switchtest.services.validation_service import ValidationService


class StubDriver:
    def __init__(self) -> None:
        self.login_attempts: list[tuple[str, str]] = []

    def connect(self) -> None: ...
    def disconnect(self) -> None: ...
    def enter_enable_mode(self) -> None: ...
    def enter_config_mode(self) -> None: ...
    def exit_config_mode(self) -> None: ...

    def run_show(self, command: str, timeout: int = 30, reauth: bool = False) -> str:
        return ""

    def apply_config(self, commands: list[str], timeout: int = 30) -> list[str]:
        return []

    def restore_baseline(self, source: str | None = None) -> None: ...

    def get_metadata(self) -> dict[str, str | None]:
        return {}

    def attempt_login(self, username: str, password: str, timeout: int = 15) -> bool:
        self.login_attempts.append((username, password))
        return False


def _context(dry_run: bool = False) -> RuntimeContext:
    return RuntimeContext(run_id="test-run", device_name="stub-device", dry_run=dry_run)


def test_trigger_failed_logins_calls_driver_for_each_attempt() -> None:
    driver = StubDriver()
    service = ExecutionService(driver=driver, validation_service=ValidationService())
    testcase = TestCaseDefinition(
        id="TC-TEST-1",
        name="lockout trigger",
        description="",
        feature="system",
        setup=[TestStep(action=TestAction.TRIGGER_FAILED_LOGINS, username="admin1", wrong_password="x", attempts=3)],
    )

    result = service.run_test(_context(), testcase)

    assert driver.login_attempts == [("admin1", "x")] * 3
    assert result.status == ResultStatus.PASS
    assert sum("FAILED_LOGIN_ATTEMPT" in line for line in result.command_log) == 3


def test_trigger_failed_logins_dry_run_does_not_call_driver() -> None:
    driver = StubDriver()
    service = ExecutionService(driver=driver, validation_service=ValidationService())
    testcase = TestCaseDefinition(
        id="TC-TEST-2",
        name="lockout trigger dry run",
        description="",
        feature="system",
        setup=[TestStep(action=TestAction.TRIGGER_FAILED_LOGINS, username="admin1", wrong_password="x", attempts=3)],
    )

    result = service.run_test(_context(dry_run=True), testcase)

    assert driver.login_attempts == []
    assert any("DRY_RUN trigger_failed_logins" in line for line in result.command_log)
