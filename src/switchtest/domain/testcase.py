from typing import Optional

from pydantic import BaseModel, Field

from switchtest.domain.enums import Severity, TestAction, ValidationType


class TestStep(BaseModel):
    action: TestAction
    commands: list[str] = Field(default_factory=list)
    seconds: Optional[int] = None


class ValidationStep(BaseModel):
    name: str
    type: ValidationType
    command: Optional[str] = None
    expected: Optional[str] = None
    pattern: Optional[str] = None
    target: Optional[str] = None
    timeout: int = 30
    reauth: bool = False


class TestCaseDefinition(BaseModel):
    id: str
    name: str
    description: str
    feature: str
    tags: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    preconditions: list[str] = Field(default_factory=list)
    setup: list[TestStep] = Field(default_factory=list)
    validations: list[ValidationStep] = Field(default_factory=list)
    cleanup: list[TestStep] = Field(default_factory=list)
    continue_on_failure: bool = False
    timeout: int = 300
    restore_baseline_after: bool = True
