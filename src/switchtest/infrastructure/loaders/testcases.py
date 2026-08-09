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
    """Substitute `$name` in every string in the testcase.

    Deliberately everything rather than a list of fields. The narrow version
    covered only a validation's `expected`/`pattern`/`target`, which was enough
    while the only variables were `$host` and `$expected_firmware` -- but a
    `$baseline_ip_lockout_threshold` in a cleanup command, or `$test_password`
    in an SNMP credential, was then passed to the switch as those literal
    characters. Nothing rejects that; the command simply does the wrong thing.

    `safe_substitute` leaves unknown names alone, so an unset `$expected_firmware`
    stays visible (and fails) instead of collapsing to an empty pattern that
    matches anything. A lone `$` -- a regex end anchor, say -- is also left as
    it is, because it is not followed by an identifier.
    """
    _substitute_in_place(payload, variables)


def _substitute_in_place(node: object, variables: dict[str, str]) -> object:
    if isinstance(node, str):
        return render_template(node, variables)
    if isinstance(node, dict):
        for key, value in node.items():
            node[key] = _substitute_in_place(value, variables)
        return node
    if isinstance(node, list):
        for index, value in enumerate(node):
            node[index] = _substitute_in_place(value, variables)
        return node
    return node
