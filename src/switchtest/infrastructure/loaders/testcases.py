from pathlib import Path

from switchtest.domain.testcase import TestCaseDefinition
from switchtest.exceptions import LoaderError
from switchtest.infrastructure.loaders.common import load_yaml_file
from switchtest.utils.templating import render_template


def load_testcase(path: Path, variables: dict[str, str] | None = None) -> TestCaseDefinition:
    payload = load_yaml_file(path)
    if variables:
        _apply_variables(payload, variables)
    try:
        return TestCaseDefinition.model_validate(payload)
    except Exception as exc:
        raise LoaderError(f"Invalid testcase file {path}: {exc}") from exc


def _apply_variables(payload: dict, variables: dict[str, str]) -> None:
    for validation in payload.get("validations") or []:
        for field_name in ("expected", "pattern", "target"):
            value = validation.get(field_name)
            if isinstance(value, str):
                validation[field_name] = render_template(value, variables)
