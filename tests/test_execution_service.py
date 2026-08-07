from switchtest.domain.enums import ResultStatus, TestAction, ValidationType
from switchtest.domain.runtime import RuntimeContext
from switchtest.domain.testcase import SnmpCredentials, TestCaseDefinition, TestStep, ValidationStep
from switchtest.services.execution_service import ExecutionService
from switchtest.services.validation_service import ValidationService


class StubDriver:
    def __init__(self, locked: bool = False) -> None:
        self.login_attempts: list[tuple[str, str]] = []
        self.applied_commands: list[str] = []
        self.ignore_errors_flags: list[bool] = []
        self.locked = locked

    def connect(self) -> None: ...
    def disconnect(self) -> None: ...
    def enter_enable_mode(self) -> None: ...
    def enter_config_mode(self) -> None: ...
    def exit_config_mode(self) -> None: ...

    def run_show(self, command: str, timeout: int = 30, reauth: bool = False) -> str:
        if command.startswith("show user"):
            return f"Account lockout     = {'Yes' if self.locked else 'No'},"
        return ""

    def apply_config(
        self, commands: list[str], timeout: int = 30, ignore_errors: bool = False
    ) -> list[str]:
        self.applied_commands.extend(commands)
        self.ignore_errors_flags.append(ignore_errors)
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


def _ensure_unlocked_case() -> TestCaseDefinition:
    return TestCaseDefinition(
        id="TC-TEST-3",
        name="ensure unlocked",
        description="",
        feature="system",
        setup=[TestStep(action=TestAction.ENSURE_UNLOCKED, username="admin1")],
    )


def test_ensure_unlocked_unlocks_a_locked_account() -> None:
    driver = StubDriver(locked=True)
    service = ExecutionService(driver=driver, validation_service=ValidationService())

    result = service.run_test(_context(), _ensure_unlocked_case())

    assert driver.applied_commands == ["user admin1 unlock"]
    assert any("was locked, now unlocked" in line for line in result.command_log)


def test_ensure_unlocked_leaves_an_unlocked_account_alone() -> None:
    driver = StubDriver(locked=False)
    service = ExecutionService(driver=driver, validation_service=ValidationService())

    result = service.run_test(_context(), _ensure_unlocked_case())

    assert driver.applied_commands == []
    assert any("already unlocked" in line for line in result.command_log)


def test_cli_step_passes_ignore_errors_through_to_the_driver() -> None:
    # Clearing leftovers from an interrupted run: deleting an account that
    # isn't there is an error the setup has to tolerate. Ordinary steps must
    # still fail loudly, or a testcase could "pass" without configuring
    # anything.
    driver = StubDriver()
    service = ExecutionService(driver=driver, validation_service=ValidationService())
    testcase = TestCaseDefinition(
        id="TC-TEST-4",
        name="snmp account setup",
        description="",
        feature="system",
        setup=[
            TestStep(action=TestAction.CLI, commands=["no user snmpv3"], ignore_errors=True),
            TestStep(action=TestAction.CLI, commands=["user snmpv3 password x sha256+aes read-write all"]),
        ],
    )

    result = service.run_test(_context(), testcase)

    assert driver.ignore_errors_flags == [True, False]
    assert result.command_log[0].startswith("CLI? no user snmpv3")


def test_dry_run_skips_snmp_validations() -> None:
    # snmp_set writes to the device, and a dry run must not -- nor should it
    # need net-snmp installed just to check a suite loads.
    driver = StubDriver()
    service = ExecutionService(driver=driver, validation_service=ValidationService())
    testcase = TestCaseDefinition(
        id="TC-TEST-5",
        name="snmp set",
        description="",
        feature="system",
        validations=[
            ValidationStep(
                name="set sysName",
                type=ValidationType.SNMP_SET,
                target="192.0.2.1",
                port=161,
                oid="sysName.0",
                value="X",
                snmp=SnmpCredentials(user="snmpv3", auth_password="x"),
            )
        ],
    )

    result = service.run_test(_context(dry_run=True), testcase)

    assert result.validation_results[0].status == ResultStatus.SKIPPED
