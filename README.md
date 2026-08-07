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
  - `port_closed`
  - `port_scan_closed`
  - `web_unreachable`
  - `tls_version`
  - `tcp_blocked`
  - `snmp_get`
  - `snmp_set`
  - `snmp_denied`
- SNMPv3 checks driven through net-snmp (the automated form of a MIB browser),
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

  - name: secureadmin
    host: 192.168.1.1
    port: 22
    username: secureadmin
    password_env: SWITCH_SECUREADMIN_PASSWORD
    platform: aos
    transport: serial
    serial_port: COM4
    serial_baudrate: 115200
    expected_prompt: "->"
    tags: [lab, secfunc, audit, console]
    connection_timeout: 15
    command_timeout: 30
    strict_host_key: false
```

Important:
- `password_env` is the name of the environment variable, not the password itself.
- `platform` currently supports `aos`.
- The framework does not provision device accounts. Any account referenced by a device entry (e.g. `lowpriv`'s `user1`) must already exist on the switch, created out-of-band, before tests run against it.
- A separate low-privilege device entry is needed whenever a testcase must prove that a restricted account is denied a privileged action — running that testcase under an admin/secureadmin account would make the check meaningless (it would always pass).
- `transport` selects how the framework holds its *own* session with the device: `ssh` (default) or `serial` (a locally attached RS-232/USB-serial console). A serial entry must also set `serial_port` (`COM4` on Windows, `/dev/ttyUSB0` on Linux); `serial_baudrate` defaults to `9600` (the AOS console default) — the lab switch runs its console at `115200`, so its entry sets that explicitly. Both are 8N1.
- A serial entry still needs `host`/`port`. They are the device's SSH service, and remain what `$host` resolves to, what network validations (`ping`, `port_closed`, `tcp_blocked`) probe, and where `trigger_failed_logins` sends its deliberately failing logins — those must arrive over the network from this machine's IP to be counted, regardless of how the driver's own session is attached.
- Use `transport: serial` when the testcase makes the device stop answering *this machine* over the network — an IP ban (TC-IA-134) drops SSH, API and WebView alike, and only an out-of-band console survives it to run the validations and the cleanup. `switchtest list-devices` prints each device's transport and the port its session uses.
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

`setup`/`cleanup` steps support these `action` types:

- `cli` — runs `commands` (a list of CLI strings) against the device. A command whose output contains an error marker fails the step, unless the step sets `ignore_errors: true` — which is for commands whose failure is acceptable, i.e. clearing leftovers from an interrupted run, where deleting something that isn't there is an error but not a problem:

  ```yaml
  setup:
    - action: cli
      ignore_errors: true       # may or may not exist yet
      commands:
        - no snmp station 192.168.1.10
        - no user snmpv3
    - action: cli               # this one must succeed
      commands:
        - user snmpv3 password ... sha256+aes read-write all allow-ssh enable
  ```

  Keep it off everywhere else: a setup command that fails silently leaves the testcase checking nothing. Steps that ran with it are logged as `CLI?` instead of `CLI`.
- `wait` — sleeps `seconds`.
- `save_config` — runs `write memory`.
- `restore_baseline` — restores the device's configured baseline.
- `reboot` — not implemented (raises an error if used).
- `trigger_failed_logins` — attempts `attempts` (default `3`) SSH logins as `username` with `wrong_password`, each expected to be rejected, without disturbing the testcase's own already-authenticated session. Used to trigger lockout-enforcement behavior for testcases like [check_lockout_enforcement_ssh.yaml](testcases/secfunc/check_lockout_enforcement_ssh.yaml), which then validates the lockout actually took effect (`show user <username>`) and was audit-logged (`show log swlog`), as opposed to [check_lockout_threshold.yaml](testcases/secfunc/check_lockout_threshold.yaml)/[check_lockout_duration.yaml](testcases/secfunc/check_lockout_duration.yaml), which only check the lockout threshold/duration *configuration*, not that a real lockout actually happens.

  Every rejected attempt counts against that account's lockout threshold on the switch, so keep `attempts` at the minimum the test needs — and never wrap login attempts in retry/fallback logic, which burns the budget several times faster than intended.
- `ensure_unlocked` — runs `show user <username>` and issues `user <username> unlock` only if it reports `Account lockout = Yes`. Put it in `setup` as well as `cleanup`: a run that dies before its cleanup leaves the account locked, and the next run would otherwise "pass" on the leftover lockout without proving anything. It checks first rather than unlocking unconditionally because `user <name> unlock` against an unlocked account can return an error, which `cli` steps treat as a failed command.

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
- `port_closed`
  Runs `nmap -Pn -sT -p <port> <target>` from the automation host and passes when the reported state is anything other than `open` (i.e. `closed` or `filtered`). Set `protocol: udp` to scan with `-sU` instead — needed for SNMP on 161, since it doesn't answer on TCP at all. Two caveats specific to UDP: the scan needs raw-socket privileges (an **elevated** `cmd` on Windows, root on Linux) or nmap can't determine a state and the validation errors out, and a silent UDP port is reported `open|filtered` rather than `closed`, so "not open" is the strongest thing this can assert there. Use this to confirm at the network level that a service is actually unreachable, as a complement to CLI-reported `disabled` state (e.g. `check_telnet_disabled.yaml` checks `show ip service`, `check_telnet_port_closed.yaml` checks the wire). Requires an `nmap` binary on the machine running `switchtest`. Set `target` (often `$host`, see [Version Templating](#version-templating)) and `port`.
- `port_scan_closed`
  Runs one `nmap -Pn -sS -sU --top-ports <n> -T4 -v <target>` and passes when **none** of the scanned ports is `open`. `--top-ports` counts per protocol, so `top_ports: 100` (the default) means the 100 most common TCP ports *and* the 100 most common UDP ports — which covers 22/23/80/443 and 161/162/123. Any port that is still open is named in the result message, so a failure says which service is still listening.

  ```yaml
  - name: 포트스캔 - 상위 100개 tcp/udp 포트 중 열린 것 없음
    type: port_scan_closed
    target: $host
    top_ports: 100
    timeout: 600
  ```

  - **Must run elevated.** `-sS` and `-sU` both need raw sockets; from an ordinary shell nmap refuses the scan, and the validation errors out rather than reporting a falsely clean result.
  - `open|filtered` — what a silent UDP port looks like — is not counted as open.
  - `-Pn` matters more here than for `port_closed`: a device with every service switched off may not answer host discovery either, and nmap would otherwise skip it as "down", which would look like "nothing open" for the wrong reason.
  - Set a generous `timeout` (the testcase uses 600s). UDP scanning is bounded by the target's ICMP rate limiting, not by nmap; the timeout message says so.
  - This is a **bounded smoke check, not proof about all 65535 ports** — a service on an uncommon port is outside what it sees. Use `port_closed` when a specific port must be named in the evidence, and this when the claim is "nothing common is listening" (see [check_ip_service_disabled_enforcement.yaml](testcases/secfunc/check_ip_service_disabled_enforcement.yaml)). Full-range UDP (`-p-`) is deliberately not offered: it takes hours and `-T5` would just abort at its 15-minute host timeout.
- `web_unreachable`
  Launches headless Chromium via Playwright and navigates to `http://<target>:<port>/` (or `https://` when `port` is `443`), passing when the navigation itself fails (connection refused/timed out) rather than returning any response. Use this to confirm at the browser/application layer that WebView is actually unreachable once HTTP/HTTPS is disabled (e.g. `check_http_disabled.yaml`/`check_https_enabled.yaml` check `show ip service`, `check_http_web_unreachable.yaml`/`check_https_web_unreachable.yaml` check that a browser can't load the page). Requires the `web` extra (`pip install -e .[web]`) and a one-time `playwright install chromium` on the machine running `switchtest` — that install step needs internet access, but running the check afterwards does not. Set `target` (often `$host`) and `port` (`80` or `443`).

- `tls_version`
  Captures the switch's actual TLS `ServerHello` with `tshark` (Wireshark's CLI) and passes when the negotiated version matches `expected` (default `"TLS 1.2"`). Unlike the other validation types, this needs a network interface to sniff on — set env var `SWITCHTEST_CAPTURE_INTERFACE` to a value `tshark -D` recognizes (name or index) on the machine running `switchtest`, which must also have permission to capture (typically an admin/elevated shell on Windows, or `CAP_NET_RAW`/root on Linux). Since `tshark` only sees traffic that occurs during its capture window, this validation also triggers the handshake itself — it opens a certificate-verification-skipping TLS connection to `target:port` partway through the capture, so no separate traffic generator is needed. Set `target` (often `$host`) and `port` (e.g. `443` for WebView). Not wired into any suite by default — the interface/capture-permission setup is machine-specific, so add it to a suite once `SWITCHTEST_CAPTURE_INTERFACE` is confirmed working in your environment. See [check_webview_tls_version.yaml](testcases/secfunc/check_webview_tls_version.yaml).

  Every run keeps its evidence — the `.pcapng` (openable directly in Wireshark) and a human-readable `-V` dissection of the `ServerHello` packet (`.txt`, same name) are both saved to `reports/captures/` (gitignored, one pair per run, named `tls_<target>_<port>_<UTC timestamp>.pcapng`/`.txt`) regardless of pass/fail. The saved `.pcapng` path is also included in the validation's `observed` field in the JSON/console report, so it's traceable back from a specific test run's result.
- `tcp_blocked`
  Opens a plain TCP connection to `target:port` from the machine running `switchtest` and passes when it *can't* be established — dropped (timeout) or refused. Use it to confirm that this host is being blocked at the network level, e.g. after an IP ban ([check_ip_ban_enforcement_ssh.yaml](testcases/secfunc/check_ip_ban_enforcement_ssh.yaml) uses it to show that a banned source IP can no longer reach tcp/22, which is what `ssh_dispatch_run_fatal: ... Connection timed out` looks like from the client side). Distinct from `port_closed`, which asks nmap whether a service is listening at all; this asks whether *this machine* can still reach a service that is otherwise up. Set `target` (often `$host`), `port`, and `timeout` (how long to wait before calling it dropped). No external tools needed.

- `snmp_get` / `snmp_set` / `snmp_denied`
  Talk to the switch's SNMP agent over UDP/161 with net-snmp (`snmpget`/`snmpset`), i.e. the automatable form of the MIB-browser workflow: the user, security level, auth/privacy algorithms and passwords a browser asks for in a dialog become an `snmp:` block on the validation. Requires net-snmp on `PATH` on the machine running `switchtest` (Windows: the Net-SNMP installer; Linux: the `snmp` package). See [check_snmpv3_get_set_permissions.yaml](testcases/secfunc/check_snmpv3_get_set_permissions.yaml).

  ```yaml
  - name: rw 계정으로 sysName.0 set (원래 값 자동 복구)
    type: snmp_set
    target: $host
    port: 161
    oid: sysName.0
    value: "OS6900-SNMPTEST"
    value_type: s          # net-snmp type letter: s string, i integer, ...
    snmp:
      user: snmpv3
      level: authPriv      # authPriv | authNoPriv | noAuthNoPriv
      auth_protocol: SHA-256
      priv_protocol: AES
      auth_password: "..."      # or auth_password_env: SWITCH_SNMP_PASSWORD
      # priv_password defaults to the auth password, which is what an AOS
      # account created as `sha256+aes` actually uses.
  ```

  - `snmp_get` passes when the object reads back and matches `expected` (exact) or `pattern` (regex); with neither, any value passes. The value read is kept in the result's `observed` field, so a run's JSON report records what the device actually reported — `sysName.0` for the device name and `sysDescr.0` for the OS version (the same string `show system` prints as `Description`, so `pattern: "$expected_firmware"` checks the running release without hardcoding it).
  - `snmp_set` reads the current value, writes `value`, confirms it reads back, **and then puts the original value back**. Restoring in the validation rather than in `cleanup` keeps the object modified for the shortest possible window and means the testcase doesn't have to hardcode whatever the device happened to be set to. If the restore fails, the validation errors rather than quietly leaving the device changed.
  - `snmp_denied` asserts the agent refuses this account: with a `value` it attempts a SET (the read-only-account case), without one a GET. An explicit refusal (`notWritable`, `noAccess`, USM authentication failure) passes. No answer at all also passes but is flagged in the result message, since it can equally mean SNMP is switched off or the request was filtered. If the write unexpectedly succeeds, the original value is restored before the validation reports the failure.

  Passwords may be inline (`auth_password`) or from the environment (`auth_password_env`). Inline is reasonable for the throwaway accounts a testcase creates and deletes itself, as `check_snmpv3_get_set_permissions.yaml` does; use the env form for anything longer lived. Either way the values are redacted out of validation output before it reaches the reports.

#### `tls_version` setup on Windows

Wireshark's installer doesn't always add itself to `PATH`, so `tshark` (and `tshark -D`, used to list capture interfaces) can fail with `'tshark' is not recognized...` even when Wireshark is installed. Fix it in `cmd`:

```cmd
REM Confirm tshark.exe exists (adjust if installed elsewhere):
dir "C:\Program Files\Wireshark\tshark.exe"

REM Add it to PATH for just this cmd window:
set PATH=%PATH%;C:\Program Files\Wireshark
tshark -v
tshark -D

REM Add it to PATH permanently (admin cmd; only affects new cmd windows):
setx PATH "%PATH%;C:\Program Files\Wireshark" /M
```

`tshark -D` lists every capture-capable interface, including virtual/unrelated ones (Bluetooth, loopback, remote-capture plugins like `sshdump`/`ciscodump`). Pick the one actually facing the switch — cross-check with `ipconfig` to find which adapter has an IP in the switch's subnet (e.g. `192.168.1.x` for `SWITCH_HOST=192.168.1.1`), then set:

```cmd
set SWITCHTEST_CAPTURE_INTERFACE=이더넷
```

(either the interface name as `tshark -D` prints it, e.g. `이더넷`/`Wi-Fi`, or its list number, e.g. `10`, both work with `tshark -i`). Capturing itself needs an elevated/admin `cmd` window even after `tshark -D` succeeds.

Each validation also supports:

- `timeout` — per-command timeout in seconds (default `30`). Bump this for commands that return large output (e.g. `show log swlog`).
- `protocol` — `tcp` (default) or `udp`, for `port_closed`.
- `top_ports` — how many of the most common ports to scan per protocol (default `100`), for `port_scan_closed`.
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

The same mechanism substitutes `$host` with the device's `host` from `configs/devices.yaml`, so `target` fields (e.g. on a `port_closed` validation) point at whichever device the suite is run against instead of a hardcoded IP:

```yaml
validations:
  - name: Telnet port 23 is not open
    type: port_closed
    target: $host
    port: 23
```

Notes:
- This only substitutes `expected`/`pattern`/`target` fields inside `validations`, not `command` or `setup`/`cleanup` steps.
- `validate-testcase`/`validate-suite` don't have a device context, so they leave `$expected_firmware`/`$host` as a literal string — that's expected, it's still valid YAML/schema. Only `run` (which always has a `--device`) performs the substitution.
- If a device has no `expected_firmware` set, `$expected_firmware` is left unsubstituted, so any testcase referencing it fails visibly against that device — set `expected_firmware` on any device you intend to run firmware-version testcases against. (It is deliberately *not* replaced with an empty string: an empty `pattern` matches anything, which would turn a missing version into a silently passing check.)
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
| `secfunc_service_disable.yaml` | 4.1 | Remote-service disable *enforcement* — **must** run with `--device secureadmin` (serial console). It switches off every IP service, so SSH/API/WebView all go dead for the duration; see [Example 6](#example-6-run-the-service-disable-enforcement-check) |
| `secfunc_snmp.yaml` | 4.x | SNMPv3 account/station creation + audit (TC-SM-42) and net-snmp get/set permission checks (TC-SM-43) — **must** run with `--device secureadmin`; see [Example 7](#example-7-run-the-snmpv3-checks) |
| `secfunc_lockout.yaml` | 1.3.3 / 1.3.4 | Account-lockout and IP-ban *enforcement* checks — **must** run with `--device secureadmin`, which is attached over the **serial console**. They lock `admin1`, so the suite can't be connected as `admin1` (that would lock its own session), and reading swlog needs secureadmin. The IP-ban testcase bans this machine's own IP; see [Example 5](#example-5-run-the-account-lockout-and-ip-ban-enforcement-checks) |

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

### Example 5: Run the account-lockout and IP-ban enforcement checks

The `secureadmin` device is attached over the **serial console** (`COM4`, `115200` 8N1 in this lab), so connect the console cable before running this suite. If the cable enumerates as a different port on your machine, update `serial_port` in [configs/devices.yaml](configs/devices.yaml) — `mode` in `cmd.exe`, or Device Manager → Ports, lists what's available:

```cmd
set SWITCH_SECUREADMIN_PASSWORD=...
venv\Scripts\switchtest run --device secureadmin --suite suites\secfunc_lockout.yaml --report-dir reports --json reports\secfunc_133_result.json
```

Two testcases run in order:

- **TC-IA-133** deliberately fails 3 SSH logins as `admin1` to confirm the *account* really locks, verifies it from the `secureadmin` session (`show user admin1`, `show log swlog`), then unlocks `admin1` again.
- **TC-IA-134** fails 6 logins to confirm the *source IP* gets banned — a separate mechanism that blocks the whole IP regardless of account — verifies tcp/22 is now unreachable from this host (`tcp_blocked`) plus the `Banning ...` swlog entry, then runs `aaa switch-access banned-ip all release`.

`--device secureadmin` is required: the account under test (`admin1`) can't also be the one holding the session that observes and unlocks it.

⚠️ **TC-IA-134 bans the machine you run it from.** Every network path to the switch — SSH, API, WebView — goes dead from this host for the duration. The suite survives it because `secureadmin` runs over the serial console, which is out-of-band and unaffected by the ban, so the validations and the `banned-ip all release` cleanup still get through. The failed logins themselves still go out over SSH (`attempt_login`); that's what the switch counts and bans. If the cleanup doesn't run (process killed mid-test), the IP stays banned and nothing on the network can reconnect — release it from the console with `aaa switch-access banned-ip all release`.

TC-IA-133 brackets itself with `aaa switch-access ip-lockout-threshold` (setup raises it to `15`, cleanup restores `6`) so its own 3 failures can't trip the IP ban as a side effect; TC-IA-134 pins the threshold to `6` in setup because tripping that ban is exactly what it's testing. `omniswitch_api_poc`'s API/WebView equivalents of both checks manage the threshold the same way, so every one of them is self-contained and safe to run alone, in any order, or repeatedly.

Before relying on this check, confirm one `attempt_login()` registers as exactly one bad attempt on the switch (SSH libraries can negotiate several auth methods per connection, which the switch may count separately):

```cmd
set SWITCH_SECUREADMIN_PASSWORD=...
venv\Scripts\python.exe scripts\verify_failed_login_counting.py
```

It reads `admin1`'s `Password bad attempts` counter, makes a single failed login, and reports the delta — expected `1`.

### Example 6: Run the service-disable enforcement check

Needs the serial console cable (the `secureadmin` device entry) and `nmap`. Run it from an **elevated** `cmd`: the port scan uses `-sS -sU`, which needs raw-socket privileges.

```cmd
set SWITCH_SECUREADMIN_PASSWORD=...
venv\Scripts\switchtest run --device secureadmin --suite suites\secfunc_service_disable.yaml --report-dir reports --json reports\secfunc_41b_result.json
```

**TC-SM-41B** runs `ip service all admin-state disable`, then proves the switch really stopped answering: tcp/22 and tcp/443 can't be connected to (`tcp_blocked`), a browser can't load WebView (`web_unreachable`), one `nmap -sS -sU --top-ports 100 -T4` finds nothing open across the 100 most common TCP *and* UDP ports (`port_scan_closed`), `show ip service` no longer says `enabled`, and swlog carries `cmd: ip service all admin-state disable, result: SUCCESS`. Cleanup restores the baseline service posture explicitly (ssh/https/snmp/ntp back on; telnet/ftp/http stay off) rather than blanket-enabling everything, which would switch on services the CIS suite requires disabled.

⚠️ **This one takes the switch off the network for the duration.** Only the console session survives it, which is why `--device secureadmin` is mandatory. If cleanup doesn't run, re-enable from the console: `ip service ssh admin-state enable`, `ip service https admin-state enable`.

### Example 7: Run the SNMPv3 checks

Needs the serial console cable and, for TC-SM-43, net-snmp on `PATH` (`snmpget -V` should work):

```cmd
set SWITCH_SECUREADMIN_PASSWORD=...
venv\Scripts\switchtest run --device secureadmin --suite suites\secfunc_snmp.yaml --report-dir reports --json reports\secfunc_snmp_result.json
```

- **TC-SM-42** creates an SNMPv3 account (`sha256+aes`, read-write) and a trap station from the console, then confirms both commands landed in swlog as `result: SUCCESS` — the station command's success being the point of the check — and that `show snmp station` / `show user snmpv3` reflect them. Cleanup deletes both.
- **TC-SM-43** is the MIB-browser workflow, automated: net-snmp sends SNMPv3 authPriv (SHA-256 + AES) requests to UDP/161 and checks that the read-write account can `get` and `set` `sysName.0`, that the read-only account can `get` but is **refused** on `set`, and that `sysName` is back to its original value afterwards. It creates and deletes its own accounts, so it doesn't depend on TC-SM-42 having run.

Both testcases pre-clean with an `ignore_errors` step, so an interrupted earlier run that left `snmpv3`/`snmpv3ro` behind doesn't break the next one. The station IP (`192.168.1.10`, the trap receiver = this machine) and the expected `sysName` (`OS6900`) are lab-specific — change them in the testcase YAML if the lab differs.

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
- a serial console transport ([console/client.py](src/switchtest/infrastructure/console/client.py)) for `transport: serial` devices — it drives the console's `login:`/`Password:` dialogue itself (there is no protocol-level auth over serial), logs out any stale session it finds already authenticated, answers `--More--` pagers so long output like `swlog` comes back whole, and logs out on close so the console doesn't hold an account's one allowed session — a testcase that configured anything leaves unsaved changes behind, so `exit` comes back asking for confirmation `(Y/N)` rather than logging straight out, which the logout answers `y`: leave without saving, since cleanup has already restored the running config and `write memory` would instead persist whatever a half-finished run left; `attempt_login()` deliberately stays on SSH even for these devices, because failed logins only count against this machine's IP if they arrive over the network,
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
- the serial transport assumes a console port attached to the machine running the tests; remote console/terminal servers (telnet-to-console) are not supported,
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
