from pathlib import Path

from switchtest.app import RunArguments, run_application
from switchtest.exitcodes import ExitCode


def test_run_application_invalid_input_returns_invalid_input_code() -> None:
    exit_code = run_application(
        RunArguments(
            device_name="missing",
            suite_path=Path("suites/smoke.yaml"),
            devices_file=Path("configs/devices.yaml"),
            report_dir=Path("reports"),
            dry_run=True,
        )
    )
    assert exit_code == int(ExitCode.INVALID_INPUT)


def test_run_application_dry_run_returns_success() -> None:
    exit_code = run_application(
        RunArguments(
            device_name="ACSSW01",
            suite_path=Path("suites/smoke.yaml"),
            devices_file=Path("configs/devices.yaml"),
            report_dir=Path("reports"),
            dry_run=True,
        )
    )
    assert exit_code == int(ExitCode.SUCCESS)


def test_missing_expected_firmware_is_left_unsubstituted() -> None:
    from switchtest.utils.templating import render_template

    # A device entry with no expected_firmware must not turn a version pattern
    # into an empty (match-anything) one; the placeholder survives and the
    # validation fails visibly instead.
    variables = {"host": "192.0.2.1"}
    assert render_template("$expected_firmware", variables) == "$expected_firmware"
    assert render_template("$host", variables) == "192.0.2.1"
