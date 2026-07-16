import typer

from switchtest.domain.device import DeviceDefinition
from switchtest.domain.enums import DeviceSafetyState, ResultStatus, SuiteStatus
from switchtest.domain.results import SuiteResult
from switchtest.domain.runtime import RuntimeContext
from switchtest.domain.suite import SuiteDefinition
from switchtest.domain.testcase import TestCaseDefinition
from switchtest.drivers.aos import AOSSwitchDriver
from switchtest.drivers.base import BaseSwitchDriver
from switchtest.exceptions import ConfigurationError
from switchtest.infrastructure.filesystem import ensure_directory
from switchtest.infrastructure.reporting.console import render_suite_summary
from switchtest.infrastructure.reporting.json_report import write_json_report
from switchtest.infrastructure.reporting.junit_report import write_junit_report
from switchtest.services.baseline_service import BaselineService
from switchtest.services.execution_service import ExecutionService
from switchtest.services.metadata_service import MetadataService
from switchtest.services.recovery_service import RecoveryService
from switchtest.services.validation_service import ValidationService
from switchtest.utils.time import utcnow


class Orchestrator:
    def __init__(self) -> None:
        self.baseline_service = BaselineService()
        self.metadata_service = MetadataService()
        self.recovery_service = RecoveryService()

    def run_suite(
        self,
        context: RuntimeContext,
        device: DeviceDefinition,
        suite: SuiteDefinition,
        tests: list[TestCaseDefinition],
    ) -> SuiteResult:
        started_at = utcnow()
        ensure_directory(context.report_dir)
        driver = self._make_driver(device)
        metadata: dict[str, str | None] = {}
        results = []
        status = SuiteStatus.PASS
        try:
            if not context.dry_run:
                driver.connect()
                metadata = self.metadata_service.collect(driver)
                self.baseline_service.verify_baseline(driver, device)
            validation_service = ValidationService()
            execution_service = ExecutionService(driver=driver, validation_service=validation_service)
            selected_tests = _filter_tests_by_tags(tests, context.selected_tags)
            total = len(selected_tests)
            for index, testcase in enumerate(selected_tests, start=1):
                typer.echo(f"[{index}/{total}] Running {testcase.id}: {testcase.name}...")
                test_result = execution_service.run_test(context, testcase)
                results.append(test_result)
                typer.echo(
                    f"[{index}/{total}] {testcase.id} -> "
                    f"{test_result.status.value.upper()} ({test_result.duration_seconds:.1f}s)"
                )
                if test_result.status == ResultStatus.FAIL:
                    status = SuiteStatus.FAIL
                if test_result.status == ResultStatus.ERROR:
                    status = SuiteStatus.ERROR
                    if not context.dry_run:
                        try:
                            self.recovery_service.reconnect(driver)
                        except Exception:
                            context.device_state = DeviceSafetyState.UNSAFE
                if (
                    testcase.restore_baseline_after
                    and not context.dry_run
                    and context.device_state != DeviceSafetyState.UNSAFE
                ):
                    self.baseline_service.restore(context, driver, device)
                if context.device_state == DeviceSafetyState.UNSAFE:
                    status = SuiteStatus.ERROR
                    break
                if context.fail_fast and test_result.status in {ResultStatus.FAIL, ResultStatus.ERROR}:
                    break
            if not context.dry_run and context.device_state != DeviceSafetyState.UNSAFE:
                self.baseline_service.restore(context, driver, device)
        finally:
            if not context.dry_run:
                driver.disconnect()

        ended_at = utcnow()
        suite_result = SuiteResult(
            suite_name=suite.name,
            device_name=device.name,
            platform=device.platform,
            firmware_version=metadata.get("firmware_version"),
            device_model=metadata.get("device_model"),
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=(ended_at - started_at).total_seconds(),
            status=status,
            tests=results,
        )
        self._write_reports(context, suite_result)
        return suite_result

    def _make_driver(self, device: DeviceDefinition) -> BaseSwitchDriver:
        if device.platform == "aos":
            return AOSSwitchDriver(device)
        raise ConfigurationError(f"Unsupported platform: {device.platform}")

    def _write_reports(self, context: RuntimeContext, result: SuiteResult) -> None:
        if context.json_report:
            write_json_report(context.json_report, result)
        if context.junit_report:
            write_junit_report(context.junit_report, result)
        summary_path = context.report_dir / f"{context.run_id}.summary.txt"
        summary_path.write_text(render_suite_summary(result), encoding="utf-8")


def _filter_tests_by_tags(
    tests: list[TestCaseDefinition],
    selected_tags: list[str],
) -> list[TestCaseDefinition]:
    if not selected_tags:
        return tests
    selected = set(selected_tags)
    return [test for test in tests if selected.intersection(test.tags)]
