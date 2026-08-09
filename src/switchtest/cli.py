from pathlib import Path

import typer

from switchtest.app import RunArguments, run_application
from switchtest.constants import DEFAULT_LAB_FILE, DEFAULT_REPORT_DIR
from switchtest.infrastructure.loaders.lab import load_lab
from switchtest.infrastructure.loaders.suites import load_suite
from switchtest.infrastructure.loaders.testcases import load_testcase

app = typer.Typer(help="Automated functional testing for network switches")


@app.command("run")
def run(
    device: str = typer.Option(..., "--device", help="Account role from the lab config"),
    suite: Path = typer.Option(..., "--suite", exists=True, file_okay=True, dir_okay=False),
    lab_file: Path = typer.Option(DEFAULT_LAB_FILE, "--lab"),
    report_dir: Path = typer.Option(DEFAULT_REPORT_DIR, "--report-dir"),
    json_report: Path | None = typer.Option(None, "--json"),
    junit_report: Path | None = typer.Option(None, "--junit"),
    fail_fast: bool = typer.Option(False, "--fail-fast"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    tag: list[str] = typer.Option([], "--tag"),
) -> None:
    raise typer.Exit(
        run_application(
            RunArguments(
                device_name=device,
                suite_path=suite,
                lab_file=lab_file,
                report_dir=report_dir,
                json_report=json_report,
                junit_report=junit_report,
                fail_fast=fail_fast,
                dry_run=dry_run,
                tags=tag,
            )
        )
    )


@app.command("list-devices")
def list_devices(lab_file: Path = typer.Option(DEFAULT_LAB_FILE, "--lab")) -> None:
    for device in load_lab(lab_file).devices().values():
        attachment = (
            f"{device.serial_port}@{device.serial_baudrate}"
            if device.transport.value == "serial"
            else f"{device.host}:{device.port}"
        )
        typer.echo(f"{device.name}\t{device.username}\t{device.transport.value}\t{attachment}")


@app.command("show-config")
def show_config(lab_file: Path = typer.Option(DEFAULT_LAB_FILE, "--lab")) -> None:
    """Print the values testcases substitute, so a wrong one can be spotted
    before a cleanup uses it to 'restore' the switch to something it never was."""
    for name, value in sorted(load_lab(lab_file).variables().items()):
        typer.echo(f"${name}\t{value}")


@app.command("validate-suite")
def validate_suite(suite: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False)) -> None:
    definition = load_suite(suite)
    typer.echo(f"Valid suite: {definition.name} ({len(definition.tests)} tests)")


@app.command("validate-testcase")
def validate_testcase(
    testcase: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
) -> None:
    definition = load_testcase(testcase)
    typer.echo(f"Valid testcase: {definition.id} {definition.name}")


if __name__ == "__main__":
    app()
