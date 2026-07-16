# switchtest

`switchtest` is a Python-based CLI framework for automating functional and security validation of network switches over SSH.

It is designed to let you define switch checks in YAML, run them against a real device, and generate machine-readable reports for engineering teams, QA, and CI/CD pipelines.

## What The Project Is About

This project exists to make switch validation repeatable, scriptable, and safe enough for regular use during:

- firmware upgrade validation,
- pre-production acceptance testing,
- regression testing,
- CIS-aligned hardening checks,
- lab smoke testing,
- CI/CD gating for network change workflows.

Instead of manually typing commands on a switch and checking output by eye, `switchtest` lets you:

1. define tests in YAML,
2. connect to a switch over SSH,
3. run setup steps and verification commands,
4. evaluate expected output,
5. collect structured results,
6. export JSON and JUnit reports.

The current implementation targets a single switch at a time and includes an AOS driver tuned for Alcatel-Lucent Enterprise OmniSwitch devices running AOS8.

## Current Capabilities

The project currently supports:

- SSH-based switch access,
- declarative YAML testcases and suites,
- read-only and config-changing test steps,
- validation types:
  - `contains`
  - `not_contains`
  - `regex`
  - `equals`
  - `ping`
- JSON reporting,
- JUnit XML reporting,
- dry-run mode,
- fail-fast mode,
- environment-variable-based secrets,
- AOS-specific metadata parsing,
- CIS-aligned smoke checks for AOS8 management hardening,
- security-functional (`secfunc`) checks aligned to a numbered requirements checklist (self-test, audit, access control, etc.),
- automatic reconnect after a mid-suite connection failure,
- re-authentication handling for commands that prompt for a password mid-session (e.g. privileged audit-log access),
- live console progress (`[2/6] Running TC-ST-512: ...` / `[2/6] TC-ST-512 -> PASS (1.4s)`) as each test starts and finishes.

## Project Structure

```text
omniswitch_ci_cd/
├── configs/
│   ├── baselines/
│   ├── defaults.yaml
│   └── devices.yaml
├── reports/
├── suites/
│   ├── cis_smoke.yaml
│   ├── regression.yaml
│   ├── smoke.yaml
│   ├── suite1.yaml            # secfunc 1.x (identification/authentication)
│   ├── suite3.yaml            # secfunc 3.x (flow control)
│   ├── suite4.yaml            # secfunc 4.x (security management)
│   ├── suite5.yaml            # secfunc 5.x (self-test)
│   ├── suite7.yaml            # secfunc 7.x (data protection)
│   ├── suite8.yaml            # secfunc 8.x (audit)
│   ├── secfunc_auto.yaml      # self-test/audit checks runnable under the normal admin device
│   └── secfunc_lowpriv.yaml   # audit access-restriction check, must run under a low-privilege device
├── testcases/
│   ├── cis/
│   ├── l3/
│   ├── secfunc/
│   ├── system/
│   └── vlan/
├── tests/
└── src/
    └── switchtest/
```

## Getting Started

### Prerequisites

- Python 3.11+
- A reachable switch with SSH enabled
- Valid switch credentials
- Windows PowerShell or `cmd.exe`, or a Linux shell

### Install

From the project root:

```powershell
venv\Scripts\python.exe -m pip install -e .[dev]
venv\Scripts\switchtest --help
venv\Scripts\python.exe -m pytest
```

If the virtual environment is already activated, you can use `switchtest` directly.

## Configuration

### Devices

Devices are defined in [configs/devices.yaml](configs/devices.yaml).

Example:

```yaml
devices:
  - name: ACSSW01
    host: 192.168.1.1
    port: 22
    username: admin1
    password_env: SWITCH_SW1_PASSWORD
    enable_password_env: SWITCH_SW1_ENABLE_PASSWORD
    platform: aos
    baseline_strategy: load_config
    baseline_source: configs/baselines/core_switch.cfg
    expected_prompt: "->"
    expected_firmware: "8.10.86.R04"
    tags: [lab, core]
    connection_timeout: 15
    command_timeout: 30
    strict_host_key: false

  - name: lowpriv
    host: 192.168.1.1
    port: 22
    username: user1
    password_env: SWITCH_OS6870_USER1_PASSWORD
    platform: aos
    expected_prompt: "->"
    tags: [lab, secfunc, lowpriv]
    connection_timeout: 15
    command_timeout: 30
    strict_host_key: false
```

Important:
- `password_env` is the name of the environment variable, not the password itself.
- `platform` currently supports `aos`.
- The framework does not provision device accounts. Any account referenced by a device entry (e.g. `lowpriv`'s `user1`) must already exist on the switch, created out-of-band, before tests run against it.
- A separate low-privilege device entry is needed whenever a testcase must prove that a restricted account is denied a privileged action — running that testcase under an admin/secureadmin account would make the check meaningless (it would always pass).
- `expected_firmware` is the single source of truth for what firmware version a device is supposed to be running. Testcases reference it instead of hardcoding a version — see [Version Templating](#version-templating) below. Bump it here when the switch gets a new release; you don't need to touch any testcase files.

### Secrets

In PowerShell:

```powershell
$env:SWITCH_SW1_PASSWORD="your-password"
```

In `cmd.exe`:

```cmd
set SWITCH_SW1_PASSWORD=your-password
```

## How To Run Tests

### Run a suite

Run the standard smoke suite:

```powershell
venv\Scripts\switchtest run --device ACSSW01 --suite suites\smoke.yaml --report-dir reports --json reports\result.json --junit reports\junit.xml
```

Run the CIS-aligned suite:

```powershell
venv\Scripts\switchtest run --device ACSSW01 --suite suites\cis_smoke.yaml --report-dir reports --json reports\cis_result.json --junit reports\cis_junit.xml
```

### Dry-run

Use dry-run to validate suite loading and execution flow without making device changes:

```powershell
venv\Scripts\switchtest run --device ACSSW01 --suite suites\smoke.yaml --report-dir reports --dry-run
```

### Validate YAML files

Validate a suite:

```powershell
venv\Scripts\switchtest validate-suite suites\cis_smoke.yaml
```

Validate a testcase:

```powershell
venv\Scripts\switchtest validate-testcase testcases\cis\check_snmpv3_configured.yaml
```

### List configured devices

```powershell
venv\Scripts\switchtest list-devices
```

## Reports

Successful and failed runs produce structured artifacts in `reports/`.

Typical outputs:

- `result.json` or `cis_result.json`
- `junit.xml` or `cis_junit.xml`
- `run-<timestamp>-<id>.summary.txt`

The summary file lists a per-test breakdown, including which validation(s) failed and why:

```text
Suite: suite4
Device: ACSSW01
Platform: aos
Firmware: 8.10.86.R04 GA
Model: OS6900-X48C6
Status: fail
Pass: 3 Fail: 1 Error: 0 Skipped: 0

Tests:
  [PASS] TC-SM-41 Remote service enable/disable
  [FAIL] TC-SM-441 Firmware version display
    - working 이미지 버전: expected='8.10.86.R04' observed='8.10.86.R03 GA' (Expected '8.10.86.R04' to appear)
  [PASS] TC-SM-442 Firmware hash verification
  [PASS] TC-SM-461 Session inactivity timeout
```

### JSON report

The JSON report contains:

- suite metadata,
- device metadata,
- test-level status,
- validation-level status,
- observed output,
- expected values,
- timings,
- cleanup state.

### JUnit XML

JUnit output is suitable for CI/CD systems such as Jenkins, GitLab CI, GitHub Actions, or Azure DevOps test reporting.

## Testcase Format

Testcases are YAML files under `testcases/`.

Example: [testcases/system/login.yaml](testcases/system/login.yaml)

```yaml
id: TC-SYS-001
name: Verify management session and show system response
description: Validate that the switch accepts a session and returns key system information.
feature: system
tags: [smoke, system]
severity: high
setup: []

validations:
  - name: Show system includes description
    type: contains
    command: show system
    expected: "Description:"

cleanup: []
continue_on_failure: false
timeout: 60
```

## Validation Types

Supported validation types:

- `contains`
  Passes when `expected` exists in command output.
- `not_contains`
  Passes when `expected` does not exist in output.
- `regex`
  Passes when `pattern` matches the output.
- `equals`
  Passes when normalized output equals normalized expected text.
- `ping`
  Runs a host-side ping check instead of a switch CLI command.

Each validation also supports:

- `timeout` — per-command timeout in seconds (default `30`). Bump this for commands that return large output (e.g. `show log swlog`).
- `reauth` — set to `true` when the switch prompts for the account's password again before returning this command's output (observed on this device for privileged/audit-log commands such as `show log swlog`). The driver answers the prompt with the same password used to log in. Leave `false` for ordinary `show` commands.

## Version Templating

Testcases that check a firmware release should not hardcode the version string — write `$expected_firmware` in `expected` (or `pattern`) instead:

```yaml
validations:
  - name: Firmware version matches expected release
    type: contains
    command: show system
    expected: "$expected_firmware"
```

At run time, `switchtest run` substitutes `$expected_firmware` with the `expected_firmware` value from the `--device` entry in `configs/devices.yaml`. To test a new firmware release, update `expected_firmware` in one place (the device entry) — every testcase that references it picks up the new value automatically, no need to edit `testcases/system/check_firmware.yaml`, `testcases/secfunc/check_firmware_version.yaml`, or any other file by hand.

Notes:
- This only substitutes `expected`/`pattern` fields inside `validations`, not `command` or `setup`/`cleanup` steps.
- `validate-testcase`/`validate-suite` don't have a device context, so they leave `$expected_firmware` as a literal string — that's expected, it's still valid YAML/schema. Only `run` (which always has a `--device`) performs the substitution.
- If a device has no `expected_firmware` set, `$expected_firmware` resolves to an empty string, so any testcase referencing it will fail its `contains`/`equals` check against that device — set `expected_firmware` on any device you intend to run firmware-version testcases against.
- Model name (`OS6900-X48C6`, etc.) is not templated because no testcase checks it — it only shows up as informational metadata (`show system` → `Model:` in the summary/report).

## Suites

Suites are lists of testcase file paths.

Example: [suites/cis_smoke.yaml](suites/cis_smoke.yaml)

```yaml
name: cis_smoke
description: CIS-aligned smoke validation for AOS8 management and hardening posture
tests:
  - ../testcases/system/login.yaml
  - ../testcases/system/check_firmware.yaml
  - ../testcases/cis/check_ssh_enabled.yaml
  - ../testcases/cis/check_telnet_disabled.yaml
  - ../testcases/cis/check_http_disabled.yaml
  - ../testcases/cis/check_https_enabled.yaml
  - ../testcases/cis/check_ntp_configured.yaml
  - ../testcases/cis/check_syslog_configured.yaml
  - ../testcases/cis/check_aaa_configured.yaml
  - ../testcases/cis/check_snmpv3_configured.yaml
```

### secfunc suites

`testcases/secfunc/` testcases map to a numbered security-requirements checklist (the number appears in each testcase's `description`, e.g. `(4.4.1)`). They're grouped into suites by the top-level category number:

| Suite | Category | Covers |
|---|---|---|
| `suite1.yaml` | 1.x | Identification & authentication |
| `suite3.yaml` | 3.x | Flow control |
| `suite4.yaml` | 4.x | Security management |
| `suite5.yaml` | 5.x | Self-test |
| `suite7.yaml` | 7.x | Data protection |
| `suite8.yaml` | 8.x | Audit |
| `secfunc_auto.yaml` | 5.x / 8.x | Boot self-test and audit-generation checks runnable under the normal admin device (overlaps `suite5`/`suite8`; not yet consolidated) |
| `secfunc_lowpriv.yaml` | 8.4.1 | Audit access-restriction check — **must** run with `--device lowpriv`, never an admin account, or the check is meaningless |

## Example Workflows

### Example 1: Verify the switch firmware

Use [testcases/system/check_firmware.yaml](testcases/system/check_firmware.yaml) to confirm the expected AOS release:

```powershell
venv\Scripts\switchtest run --device ACSSW01 --suite suites\smoke.yaml --report-dir reports --json reports\result.json --junit reports\junit.xml
```

Expected metadata in the JSON report:

```json
"firmware_version": "8.10.86.R04 GA",
"device_model": "OS6900-X48C6"
```

### Example 2: Run CIS-aligned checks

```powershell
venv\Scripts\switchtest run --device ACSSW01 --suite suites\cis_smoke.yaml --report-dir reports --json reports\cis_result.json --junit reports\cis_junit.xml
```

This suite currently checks:

- management session responsiveness,
- firmware,
- SSH enabled,
- Telnet disabled,
- HTTP/WebView state,
- HTTPS/WebView enforcement,
- NTP sync,
- syslog configuration,
- AAA configuration,
- SNMPv3 posture.

### Example 3: Run a secfunc category suite

```powershell
venv\Scripts\switchtest run --device ACSSW01 --suite suites\suite5.yaml --report-dir reports --json reports\suite5_result.json
```

### Example 4: Run the low-privilege access-restriction check

Requires the `lowpriv` device account to already exist on the switch, and its password set in `SWITCH_OS6870_USER1_PASSWORD`:

```powershell
$env:SWITCH_OS6870_USER1_PASSWORD = "..."
venv\Scripts\switchtest run --device lowpriv --suite suites\secfunc_lowpriv.yaml --report-dir reports --json reports\secfunc_841_result.json
```

## How To Add A New Testcase

1. Create a YAML file under the appropriate folder in `testcases/`.
2. Define `id`, `name`, `description`, `feature`, and `validations`.
3. Add the testcase path to a suite in `suites/` — for `testcases/secfunc/`, add it to the suite matching its requirement-number category (see [secfunc suites](#secfunc-suites)) rather than creating a new suite.
4. Validate the testcase.
5. Run the suite.

If the validation reads a large or privileged log (e.g. `show log swlog`), also set a higher `timeout` (start at `90`) and check by hand whether the account being used gets re-prompted for its password — if so, set `reauth: true` on that validation.

Example:

```powershell
venv\Scripts\switchtest validate-testcase testcases\system\check_firmware.yaml
venv\Scripts\switchtest validate-suite suites\smoke.yaml
```

## How To Tune Tests To Your Switch

Network devices often vary slightly by:

- command syntax,
- output formatting,
- feature names,
- enabled services,
- prompt style.

When a testcase fails:

1. inspect the `observed` output in the JSON report,
2. compare it with the YAML `expected` or `pattern`,
3. tune the testcase to the actual CLI output.

This is especially important for CIS-aligned checks because different AOS8 builds may expose services and security settings differently.

## Exit Codes

The CLI uses structured exit codes:

- `0` success
- `1` test failure
- `2` framework error
- `3` device connection error
- `4` cleanup failure
- `5` invalid input

## Notes About The Current AOS Driver

The AOS driver in [aos.py](src/switchtest/drivers/aos.py) includes:

- metadata extraction from `show system`,
- cleanup of echoed prompt/command lines,
- retry on transient empty `show` output,
- Windows-safe SSH transport selection,
- suppression of noisy Windows close-time socket warnings from Paramiko,
- re-authentication handling for commands flagged `reauth: true` in a testcase (answers a mid-session `Password:` prompt with the login password),
- automatic session recovery: if a test errors out (including a dead/EOF'd connection), the orchestrator reconnects before running the next test in the suite instead of letting the failure cascade.

This means the current implementation is already tuned to the OmniSwitch/AOS8 behavior observed in this repository's lab runs. Note that `show log swlog` and similar large/privileged log queries can still be slow or device-specific — if you hit a timeout or an unexpected re-auth prompt on a new command, check `reauth` and `timeout` on that validation first.

## Development

Run tests:

```powershell
venv\Scripts\python.exe -m pytest
```

Run lint:

```powershell
venv\Scripts\python.exe -m ruff check .
```

## Limitations

Current limitations:

- one switch at a time,
- one platform driver (`aos`),
- CIS suite is CIS-aligned, not an official vendor-specific CIS benchmark,
- some testcases still need environment-specific tuning depending on switch configuration,
- the framework does not provision device accounts (e.g. `lowpriv`'s `user1` must be created on the switch out-of-band before tests can run),
- some `secfunc` checks depend on log history that only exists if the underlying event already happened on the device (e.g. a firmware-update audit check needs a real prior upgrade/downgrade in `swlog`) — these are precondition gaps, not code bugs, and need to be set up manually before the check will pass,
- `secfunc_auto.yaml` currently overlaps `suite5.yaml`/`suite8.yaml` (same 5.x/8.x category numbers, not yet consolidated).

## Next Steps

Useful next improvements:

- stricter AAA validation,
- stronger SNMPv3 checks,
- syslog-over-TLS validation,
- configuration drift checks,
- more AOS8 hardening testcases,
- multi-device topology testing,
- consolidate `secfunc_auto.yaml` into the category suites (`suite5.yaml`/`suite8.yaml`),
- account lifecycle (create/delete) for one-off low-privilege test accounts, run as separate `switchtest run` invocations under an admin device rather than inside a single testcase's setup/cleanup.
