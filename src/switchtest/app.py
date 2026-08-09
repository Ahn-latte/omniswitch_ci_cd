from dataclasses import dataclass, field
from pathlib import Path

import typer

from switchtest.domain.enums import ResultStatus, SuiteStatus
from switchtest.domain.runtime import RuntimeContext
from switchtest.exceptions import (
    BaselineRestoreError,
    ConnectionError,
    LoaderError,
    SwitchTestError,
)
from switchtest.exitcodes import ExitCode
from switchtest.infrastructure.loaders.lab import load_lab
from switchtest.infrastructure.loaders.suites import load_suite_testcases
from switchtest.orchestrator import Orchestrator
from switchtest.utils.time import make_run_id


@dataclass
class RunArguments:
    device_name: str
    suite_path: Path
    lab_file: Path
    report_dir: Path
    json_report: Path | None = None
    junit_report: Path | None = None
    fail_fast: bool = False
    dry_run: bool = False
    tags: list[str] = field(default_factory=list)


def run_application(args: RunArguments) -> int:
    try:
        lab = load_lab(args.lab_file)
        devices = lab.devices()
        if args.device_name not in devices:
            raise LoaderError(
                f"Unknown device '{args.device_name}' in {args.lab_file}. Devices come from "
                f"the accounts that declare a transport: {', '.join(sorted(devices)) or '(none)'}"
            )
        device = devices[args.device_name]
        suite, tests = load_suite_testcases(args.suite_path, variables=lab.variables())
        context = RuntimeContext(
            run_id=make_run_id(),
            device_name=device.name,
            suite_name=suite.name,
            report_dir=args.report_dir,
            lab_file=args.lab_file,
            fail_fast=args.fail_fast,
            dry_run=args.dry_run,
            selected_tags=args.tags,
            json_report=args.json_report,
            junit_report=args.junit_report,
        )
        result = Orchestrator().run_suite(context, device, suite, tests)
    except LoaderError as exc:
        typer.echo(f"Invalid input: {exc}", err=True)
        return int(ExitCode.INVALID_INPUT)
    except ConnectionError as exc:
        typer.echo(f"Device connection error: {exc}", err=True)
        return int(ExitCode.DEVICE_CONNECTION_ERROR)
    except BaselineRestoreError as exc:
        typer.echo(f"Cleanup failure: {exc}", err=True)
        return int(ExitCode.CLEANUP_FAILURE)
    except SwitchTestError as exc:
        typer.echo(f"Framework error: {exc}", err=True)
        return int(ExitCode.FRAMEWORK_ERROR)

    if result.status == SuiteStatus.ERROR:
        typer.echo("Suite completed with execution errors", err=True)
        return int(ExitCode.FRAMEWORK_ERROR)
    if any(test.cleanup_status == "failed" for test in result.tests):
        typer.echo("Suite completed with cleanup failures", err=True)
        return int(ExitCode.CLEANUP_FAILURE)
    if any(test.status == ResultStatus.FAIL for test in result.tests):
        typer.echo("Suite completed with test failures", err=True)
        return int(ExitCode.TEST_FAILURE)
    return int(ExitCode.SUCCESS)
