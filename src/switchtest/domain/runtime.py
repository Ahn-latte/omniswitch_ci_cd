from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from switchtest.constants import DEFAULT_LAB_FILE, DEFAULT_REPORT_DIR
from switchtest.domain.enums import DeviceSafetyState


class RuntimeContext(BaseModel):
    run_id: str
    device_name: str
    suite_name: Optional[str] = None
    report_dir: Path = DEFAULT_REPORT_DIR
    lab_file: Path = DEFAULT_LAB_FILE
    fail_fast: bool = False
    dry_run: bool = False
    selected_tags: list[str] = Field(default_factory=list)
    json_report: Optional[Path] = None
    junit_report: Optional[Path] = None
    command_logs_enabled: bool = True
    device_state: DeviceSafetyState = DeviceSafetyState.SAFE
