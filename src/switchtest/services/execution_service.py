import time

from switchtest.domain.enums import DeviceSafetyState, ResultStatus, TestAction
from switchtest.domain.results import TestResult, ValidationResult
from switchtest.domain.runtime import RuntimeContext
from switchtest.domain.testcase import TestCaseDefinition, TestStep
from switchtest.drivers.base import BaseSwitchDriver
from switchtest.exceptions import CleanupError, CommandExecutionError
from switchtest.services.validation_service import ValidationService
from switchtest.utils.time import utcnow


class ExecutionService:
    def __init__(self, driver: BaseSwitchDriver, validation_service: ValidationService) -> None:
        self.driver = driver
        self.validation_service = validation_service

    def run_test(self, context: RuntimeContext, testcase: TestCaseDefinition) -> TestResult:
        started_at = utcnow()
        command_log: list[str] = []
        validation_results: list[ValidationResult] = []
        status = ResultStatus.PASS
        error_message: str | None = None
        cleanup_status = "not_run"

        try:
            self._run_steps(context, testcase.setup, command_log)
            if testcase.setup:
                context.device_state = DeviceSafetyState.MODIFIED
            for validation in testcase.validations:
                if context.dry_run and validation.command:
                    result = ValidationResult(
                        name=validation.name,
                        status=ResultStatus.SKIPPED,
                        expected=validation.expected or validation.pattern or validation.target,
                        message="Skipped device-backed validation in dry-run mode",
                    )
                else:
                    result = self.validation_service.run_validation(self.driver, validation)
                validation_results.append(result)
                command_log.append(f"VALIDATE {validation.name}: {result.status.value}")
                if result.status == ResultStatus.FAIL:
                    status = ResultStatus.FAIL
                    if not testcase.continue_on_failure:
                        break
                if result.status == ResultStatus.ERROR:
                    status = ResultStatus.ERROR
                    break
        except Exception as exc:
            status = ResultStatus.ERROR
            error_message = str(exc)
        finally:
            try:
                self._run_steps(context, testcase.cleanup, command_log)
                cleanup_status = "passed"
                if context.device_state != DeviceSafetyState.UNSAFE:
                    context.device_state = DeviceSafetyState.SAFE
            except Exception as exc:
                cleanup_status = "failed"
                context.device_state = DeviceSafetyState.UNSAFE
                if error_message is None:
                    error_message = str(exc)
                if status == ResultStatus.PASS:
                    status = ResultStatus.ERROR

        ended_at = utcnow()
        return TestResult(
            test_id=testcase.id,
            test_name=testcase.name,
            status=status,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=(ended_at - started_at).total_seconds(),
            validation_results=validation_results,
            command_log=command_log,
            error_message=error_message,
            cleanup_status=cleanup_status,
        )

    def _run_steps(self, context: RuntimeContext, steps: list[TestStep], command_log: list[str]) -> None:
        for step in steps:
            if step.action == TestAction.WAIT:
                seconds = step.seconds or 0
                command_log.append(f"WAIT {seconds}s")
                if not context.dry_run:
                    time.sleep(seconds)
                continue
            if step.action == TestAction.CLI:
                if context.dry_run:
                    command_log.extend(f"DRY_RUN {command}" for command in step.commands)
                    continue
                outputs = self.driver.apply_config(step.commands)
                command_log.extend(f"CLI {command}" for command in step.commands)
                command_log.extend(f"OUT {output}" for output in outputs)
                continue
            if step.action == TestAction.RESTORE_BASELINE:
                if not context.dry_run:
                    self.driver.restore_baseline()
                command_log.append("RESTORE_BASELINE")
                continue
            if step.action == TestAction.REBOOT:
                raise CommandExecutionError("Reboot action is not implemented in MVP")
            if step.action == TestAction.SAVE_CONFIG:
                command_log.append("SAVE_CONFIG")
                if not context.dry_run:
                    self.driver.apply_config(["write memory"])
                continue
            if step.action == TestAction.TRIGGER_FAILED_LOGINS:
                username = step.username or ""
                if not username:
                    raise CommandExecutionError("trigger_failed_logins requires a username")
                if context.dry_run:
                    command_log.append(f"DRY_RUN trigger_failed_logins user={username} attempts={step.attempts}")
                    continue
                for attempt in range(1, step.attempts + 1):
                    succeeded = self.driver.attempt_login(username, step.wrong_password or "")
                    outcome = "unexpected SUCCESS" if succeeded else "rejected as expected"
                    command_log.append(f"FAILED_LOGIN_ATTEMPT {username} #{attempt}: {outcome}")
                continue
        if context.device_state == DeviceSafetyState.UNSAFE:
            raise CleanupError("Device is in unsafe state")
