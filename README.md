# switchtest

Security-functional test automation for Alcatel-Lucent Enterprise OmniSwitch
AOS8. Testcases are YAML; results are JSON and JUnit XML.

Together with the companion repo [`omniswitch_api_poc`](../omniswitch_api_poc)
(the same checks over the HTTPS/WebView API and a real browser), one command
runs every security-functional check against one switch:

```cmd
venv\Scripts\python.exe scripts\run_secfunc.py
```

## Install

```cmd
python -m venv venv
venv\Scripts\python.exe -m pip install -e .[dev,web]
venv\Scripts\python.exe -m playwright install chromium
```

`[web]` and the Chromium download are needed by the browser-level checks. For
the port-scan check, `nmap` must be on `PATH`. Nothing else is required —
SNMPv3 goes through pysnmp, which `pip install` brings in.

## Configure

One file holds everything: switch address, accounts, and the settings cleanups
restore the switch to.

```cmd
copy configs\lab.example.yaml configs\lab.yaml
```

Edit it, then check what the testcases will actually see:

```cmd
venv\Scripts\switchtest show-config     # every $variable, resolved
venv\Scripts\switchtest list-devices    # the sessions these accounts produce
```

`configs/lab.yaml` is gitignored. Accounts marked `provision:` are created
before the run and deleted after, so they need not exist beforehand.

> The `baseline:` block describes **this** switch, not AOS defaults. Cleanups
> write those values back, so a wrong one is worse than no run at all. Check
> them against `show user lockout-setting`, `show session config` and
> `show swlog` first.

Some checks need hardware:

| Need | Used by |
|---|---|
| Serial console cable (`console.port`) | everything in `secfunc_console.yaml`, and the API repo's IP-ban tests |
| `nmap` on `PATH`, **elevated** shell | TC-SM-41B's port scan (`-sS`/`-sU` need raw sockets) |
| `tshark` + `capture_interface` set | TC-DP-713 (TLS handshake capture) |

## Run

Everything, both repos, in the right order:

```cmd
venv\Scripts\python.exe scripts\run_secfunc.py
venv\Scripts\python.exe scripts\run_secfunc.py --list          # show the plan
venv\Scripts\python.exe scripts\run_secfunc.py --skip-console  # no cable attached
venv\Scripts\python.exe scripts\run_secfunc.py --phase switch-ssh
```

Or one suite at a time:

```cmd
venv\Scripts\switchtest run --device admin       --suite suites\secfunc_all_ssh.yaml
venv\Scripts\switchtest run --device lowpriv     --suite suites\secfunc_lowpriv.yaml
venv\Scripts\switchtest run --device secureadmin --suite suites\secfunc_console.yaml
```

Add `--json reports\out.json`, `--junit reports\out.xml`, `--fail-fast`, or
`--dry-run` (validates the YAML and touches nothing).

### Why it runs in that order

The runner is not just two tools called in sequence. Three constraints fix the
order, and getting them wrong produces failures that have nothing to do with
the switch:

1. **Some checks break the switch on purpose.** TC-SM-41B turns off every IP
   service; TC-IA-134 bans this machine's IP. Everything reachable only over
   the network has to finish first.
2. **One serial cable.** Both repos want it, so those phases never overlap —
   which is also why nothing runs in parallel.
3. **Accounts cannot create themselves.** The low-privilege checks log in as
   accounts the runner provisions beforehand and removes afterwards, including
   after a crash.

| # | Phase | Session | What it does |
|---|---|---|---|
| 1 | `password-change` | console → SSH → API → browser | same password-change policy over all four transports, one at a time |
| 2 | `switch-ssh` | SSH, `admin` | 25 testcases; nothing destructive |
| 3 | `switch-lowpriv` | SSH, `lowpriv` | audit access restriction |
| 4 | `api-network` | HTTPS + browser | needs WebView up, so it precedes phase 6 |
| 5 | `api-console` | HTTPS + console | bans this host's IP, releases it over the console |
| 6 | `switch-console` | Serial, `secureadmin` | password history, SNMP, lockout, service disable, IP ban — in that order |

Phase 1 runs the same policy check over console, SSH, API and browser in that
order rather than together: all four change one account's password, so
overlapping them would collide. Every password it tries is invalid, so nothing
actually changes. Progress is shown per transport as it goes.

> **If a run is killed mid-phase**, the switch can be left banning this machine
> or with its services off. Recover from the console:
> `aaa switch-access banned-ip all release` and
> `ip service ssh admin-state enable`.

## Testcases

### `suites/password_change_policy.yaml` — all four transports (1 testcase × 4)

`TC-IA-123` (password-change policy: every invalid password refused) run over
console, then SSH, then — in the API repo — API and browser. Phase 1 of the
integrated run.

### `suites/secfunc_all_ssh.yaml` — SSH, `admin` (25)

| ID | Name |
|---|---|
| `TC-IA-121` | Secure password policy enforcement |
| `TC-IA-122` | Password policy enforcement on new account creation |
| `TC-IA-131` | Authentication failure lockout threshold |
| `TC-IA-132` | Configurable lockout duration |
| `TC-IA-151` | Weak crypto algorithm rejected for password storage |
| `TC-FC-311` | IP-based ACL policy configuration |
| `TC-FC-312` | IEEE 802.1Q VLAN tagging |
| `TC-SM-41` | Remote service enable/disable |
| `TC-SM-441` | Firmware version display |
| `TC-SM-442` | Firmware hash verification |
| `TC-SM-461` | Session inactivity timeout |
| `TC-ST-511` | Hardware self-test at boot |
| `TC-ST-512` | Process self-test at boot |
| `TC-ST-513` | On-demand hardware and process self-test |
| `TC-ST-521` | Firmware image integrity check at boot |
| `TC-ST-523` | Config file integrity check on backup/restore |
| `TC-DP-711` | Encrypted channel for remote access |
| `TC-DP-712` | Syslog over TLS |
| `TC-DP-713` | WebView TLS handshake negotiates TLS 1.2 — needs `capture_interface` |
| `TC-DP-716` | TLS 1.2 or higher |
| `TC-DP-717` | SSH v2 support |
| `TC-AU-811` | Audit data generation |
| `TC-AU-821` | Audit data required fields |
| `TC-AU-831` | Audit trail overwrite on threshold exceed |
| `TC-AU-842` | Audit data export to external log server |

### `suites/secfunc_lowpriv.yaml` — SSH, `lowpriv` (1)

| ID | Name |
|---|---|
| `TC-AU-841` | Audit data access restriction (low-privilege account) |

### `suites/secfunc_console.yaml` — serial console, `secureadmin` (6)

Order matters here; each entry cuts this machine off the switch a little more.

| ID | Name |
|---|---|
| `TC-IA-124` | Password history prevents reuse of a recent password |
| `TC-SM-42` | SNMPv3 account and trap station are created and audited |
| `TC-SM-43` | SNMPv3 get/set works for read-write and is refused for read-only |
| `TC-IA-133` | SSH lockout actually triggers after 3 failed attempts |
| `TC-SM-41B` | Disabling every IP service actually blocks all network management |
| `TC-IA-134` | SSH IP ban actually triggers at the IP lockout threshold |

> **`TC-IA-124` changes the `admin` account's real password** to a new value and
> restores it, and it assumes the account's current password equals
> `$test_password`. It runs over the console so that even a failed restore can
> be fixed out-of-band. If your `admin` password differs, exclude it
> (`--phase` without `switch-console`, or `--tag`) or align the value.

### API and WebView transports (in `omniswitch_api_poc`)

The same behaviours through the HTTPS API and a real browser — password policy,
account lockout, IP ban, menu visibility. See that repo's README. Run by the
`password-change`, `api-network` and `api-console` phases above.

### Other suites

`suites/cis_smoke.yaml` (CIS-aligned management hardening), plus
`suites/smoke.yaml` and the numbered `suite1/3/4/5/7/8.yaml` groupings, which
slice the same secfunc testcases by requirement section.

## Writing testcases

A testcase is `setup` → `validations` → `cleanup`. Validation types:
`contains`, `not_contains`, `regex`, `equals`, `ping`, `port_closed`,
`port_scan_closed`, `web_unreachable`, `web_reachable`, `api_unreachable`,
`tls_version`, `tcp_blocked`, `snmp_get`, `snmp_set`, `snmp_denied`.

Two rules the existing testcases follow:

- **Never hardcode a lab value.** Use `$host`, `$station_ip`, `$system_name`,
  `$test_password`, `$<role>_user`, `$baseline_*` — `switchtest show-config`
  lists them all. A number written into eight testcases independently is a
  number that will eventually disagree with itself.
- **Whatever the setup changes, the cleanup restores** — to a `$baseline_*`
  value, not a literal. Accounts a testcase needs are created by that testcase
  and deleted by it.

```cmd
venv\Scripts\switchtest validate-testcase testcases\secfunc\check_ip_service.yaml
venv\Scripts\switchtest validate-suite suites\secfunc_all_ssh.yaml
venv\Scripts\python.exe -m pytest
```
