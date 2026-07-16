from pathlib import Path

from switchtest.domain.suite import SuiteDefinition
from switchtest.domain.testcase import TestCaseDefinition
from switchtest.exceptions import LoaderError
from switchtest.infrastructure.loaders.common import load_yaml_file, resolve_relative_path
from switchtest.infrastructure.loaders.testcases import load_testcase


def load_suite(path: Path) -> SuiteDefinition:
    payload = load_yaml_file(path)
    try:
        return SuiteDefinition.model_validate(payload)
    except Exception as exc:
        raise LoaderError(f"Invalid suite file {path}: {exc}") from exc


def load_suite_testcases(
    path: Path, variables: dict[str, str] | None = None
) -> tuple[SuiteDefinition, list[TestCaseDefinition]]:
    suite = load_suite(path)
    tests: list[TestCaseDefinition] = []
    for test_ref in suite.tests:
        test_path = resolve_relative_path(path, test_ref)
        tests.append(load_testcase(test_path, variables=variables))
    if not tests:
        raise LoaderError(f"Suite {path} does not contain any tests")
    return suite, tests
