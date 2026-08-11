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

## Commissioning a factory-reset switch

Before any of the below can run, the switch needs an address, services and
accounts. Straight out of a factory reset it has none of those, and no IP
address either — the serial console is the only way in:

```cmd
venv\Scripts\python.exe scripts\commission.py
```

Run it **once**, right after the reset. It is deliberately not idempotent: the
factory password works exactly once, because AOS forces a policy-compliant
change before it grants any session at all.

Three things it verifies rather than merely configures, because this is the
only moment they can be observed:

1. **The password policy is enforced during the forced first change.** Each
   rule is probed with a violating password inside that dialogue, and the
   switch's own rejection message is recorded. A switch that accepts a weak
   password here has a policy that misses the path an installer actually walks.
2. **The station is reachable** from the switch once addressing is up.
3. **Nothing is listening** before services are switched on. This runs after
   addressing but *before* `aaa authentication default local` — that command
   turns SNMP on, so scanning afterwards would find UDP/161 open and report a
   finding that isn't one.

It then creates the accounts without `provision:` (the provisioned ones are
made and removed per-run by `run_secfunc.py`) and saves the configuration —
the one place saving is right, since commissioning must survive a reboot.

Configured by the `commissioning:` block in `lab.yaml`: factory credentials,
the password to set (`12#qweASD`, which must match
`accounts.secureadmin.password`), the management address, and the ports to
bounce. Add `--skip-scan` if you cannot run elevated; results land in
`reports/commission.json`.

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

### `suites/secfunc_all_ssh.yaml` — SSH, `admin` (17)

| ID | Name |
|---|---|
| `TC-IA-121` | Secure password policy enforcement |
| `TC-IA-122` | Password policy enforcement on new account creation |
| `TC-IA-131` | Authentication failure lockout threshold |
| `TC-IA-132` | Configurable lockout duration |
| `TC-IA-151` | Weak crypto algorithm rejected for password storage |
| `TC-FC-312` | IEEE 802.1Q VLAN tagging |
| `TC-SM-41` | Remote service enable/disable |
| `TC-SM-441` | Firmware version display |
| `TC-SM-442` | Firmware hash verification |
| `TC-SM-461` | Session inactivity timeout |
| `TC-ST-513` | On-demand hardware and process self-test |
| `TC-DP-711` | Encrypted channel for remote access |
| `TC-DP-712` | Syslog over TLS |
| `TC-DP-713` | WebView TLS handshake negotiates TLS 1.2 — needs `capture_interface` |
| `TC-DP-716` | TLS 1.2 or higher |
| `TC-DP-717` | SSH v2 support |
| `TC-AU-842` | Audit data export to external log server |

Nothing here reads `show log swlog`. That command is secureadmin-only, so as
`admin` it just drops the session — the eight testcases that need swlog as
evidence live in the console suite below.

### `suites/secfunc_lowpriv.yaml` — SSH, `lowpriv` (1)

| ID | Name |
|---|---|
| `TC-AU-841` | Audit data access restriction (low-privilege account) |

This is the one testcase whose point is that swlog *cannot* be read: refusal is
the pass condition. Do not confuse it with the eight below, which are the
opposite — they only work if swlog can be read.

### `suites/secfunc_console.yaml` — serial console, `secureadmin` (14)

Two different reasons put a testcase here: it takes this machine off the
network (so only an out-of-band session can verify and recover), or it reads
`show log swlog`, which only `secureadmin` may do.

Order matters; the destructive entries are last and must stay there.

| ID | Name | Why console |
|---|---|---|
| `TC-IA-124` | Password history prevents reuse of a recent password | global setting |
| `TC-FC-311` | IP-based ACL policy configuration | swlog |
| `TC-SM-42` | SNMPv3 account and trap station are created and audited | swlog |
| `TC-SM-43` | SNMPv3 get/set works for read-write and is refused for read-only | swlog |
| `TC-ST-511` | Hardware self-test at boot | swlog |
| `TC-ST-512` | Process self-test at boot | swlog |
| `TC-ST-521` | Firmware image integrity check at boot | swlog |
| `TC-ST-523` | Config file integrity check on backup/restore | swlog |
| `TC-AU-811` | Audit data generation | swlog |
| `TC-AU-821` | Audit data required fields | swlog |
| `TC-AU-831` | Audit trail overwrite on threshold exceed | swlog |
| `TC-IA-133` | SSH lockout actually triggers after 3 failed attempts | locks an account |
| `TC-SM-41B` | Disabling every IP service actually blocks all network management | kills the network |
| `TC-IA-134` | SSH IP ban actually triggers at the IP lockout threshold | bans this host |

> **Known firmware bug — `TC-AU-811` is expected to fail.** Its "firmware
> update" check looks for `AOS upgrade or downgrade complete` in swlog, and
> this firmware never writes that record even when an upgrade really happens.
> The failure is the finding: leave it failing rather than relaxing the
> assertion. Its other four checks (login success/failure, integrity, service
> enable/disable) pass.

> **`TC-IA-124` assumes the `admin` account's current password equals
> `$test_password`**, since the reuse case attempts a change to that same
> value. It never actually changes the password — rejection is the pass
> condition — so there is nothing to restore. If your `admin` password
> differs, exclude it (`--phase` without `switch-console`, or `--tag`) or
> align the value.

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

---

## 한국어 (Korean)

# switchtest

Alcatel-Lucent Enterprise OmniSwitch AOS8용 보안 기능(security-functional) 테스트
자동화 도구입니다. 테스트케이스는 YAML로 작성하고, 결과는 JSON과 JUnit XML로
출력됩니다.

동반 저장소인 [`omniswitch_api_poc`](../omniswitch_api_poc)(동일한 점검을
HTTPS/WebView API와 실제 브라우저로 수행)와 함께 쓰면, 명령 하나로 스위치
한 대에 대한 모든 보안 기능 점검을 실행할 수 있습니다:

```cmd
venv\Scripts\python.exe scripts\run_secfunc.py
```

### 설치

```cmd
python -m venv venv
venv\Scripts\python.exe -m pip install -e .[dev,web]
venv\Scripts\python.exe -m playwright install chromium
```

`[web]`과 Chromium 다운로드는 브라우저 레벨 점검에 필요합니다. 포트 스캔
점검을 위해서는 `nmap`이 `PATH`에 있어야 합니다. 그 외에는 별도로 필요한
것이 없습니다 — SNMPv3는 pysnmp를 통해 동작하며, 이는 `pip install` 시
함께 설치됩니다.

### 설정

파일 하나에 모든 것이 들어 있습니다: 스위치 주소, 계정, 그리고 정리
(cleanup) 시 스위치를 되돌릴 설정 값들입니다.

```cmd
copy configs\lab.example.yaml configs\lab.yaml
```

파일을 수정한 뒤, 테스트케이스가 실제로 무엇을 보게 될지 확인하세요:

```cmd
venv\Scripts\switchtest show-config     # 모든 $변수, 해석된 값
venv\Scripts\switchtest list-devices    # 이 계정들로 생성되는 세션 목록
```

`configs/lab.yaml`은 gitignore 대상입니다. `provision:`으로 표시된 계정은
실행 전에 생성되고 실행 후 삭제되므로, 미리 존재할 필요가 없습니다.

> `baseline:` 블록은 AOS 기본값이 아니라 **현재 이 스위치**의 상태를
> 기술합니다. 정리(cleanup) 단계에서 이 값들을 그대로 되돌려 쓰므로, 잘못된
> 값은 아예 실행하지 않는 것보다 더 나쁩니다. `show user lockout-setting`,
> `show session config`, `show swlog`로 먼저 값을 확인하세요.

일부 점검은 하드웨어가 필요합니다:

| 필요한 것 | 사용하는 곳 |
|---|---|
| 시리얼 콘솔 케이블 (`console.port`) | `secfunc_console.yaml`의 모든 항목, API 저장소의 IP-ban 테스트 |
| `nmap`이 `PATH`에 있고 **관리자 권한** 셸 | TC-SM-41B의 포트 스캔 (`-sS`/`-sU`는 raw socket 필요) |
| `tshark` + `capture_interface` 설정 | TC-DP-713 (TLS 핸드셰이크 캡처) |

### 공장 초기화된 스위치 세워 올리기

아래의 어떤 것도 실행하려면 스위치에 주소·서비스·계정이 있어야 합니다. 공장
초기화 직후에는 그 무엇도 없고 IP 주소조차 없어서, 시리얼 콘솔이 유일한
진입 경로입니다:

```cmd
venv\Scripts\python.exe scripts\commission.py
```

초기화 직후 **한 번만** 실행합니다. 의도적으로 멱등하지 않습니다 — AOS가
세션을 주기 전에 정책을 만족하는 비밀번호로 바꾸도록 강제하므로, 공장
비밀번호는 딱 한 번만 유효합니다.

단순 설정이 아니라 **검증**하는 항목이 셋 있습니다. 이 순간에만 관측
가능하기 때문입니다:

1. **강제 첫 변경 과정에서 비밀번호 정책이 실제로 적용되는지.** 각 규칙을
   위반하는 비밀번호를 그 대화 안에서 하나씩 시도하고, 스위치가 내놓는 거부
   메시지를 그대로 기록합니다. 여기서 취약한 비밀번호가 통과한다면, 설치자가
   실제로 걷는 경로를 정책이 못 지키고 있다는 뜻입니다.
2. **주소 설정 후 PC와 통신이 되는지** (스위치에서 ping).
3. **서비스를 켜기 전에는 아무것도 열려 있지 않은지** (포트스캔). 이 검사는
   주소 설정 뒤, 그러나 `aaa authentication default local` **앞**에 실행합니다 —
   이 명령이 SNMP를 켜기 때문에, 뒤에서 스캔하면 UDP/161이 열린 것으로 나와
   발견이 아닌 것을 발견으로 보고하게 됩니다.

그 다음 `provision:`이 없는 계정을 생성하고(있는 계정은 `run_secfunc.py`가 매
실행 생성·삭제) 설정을 저장합니다. 저장이 옳은 유일한 경우입니다 — 브링업은
재부팅을 견뎌야 하니까요.

설정은 `lab.yaml`의 `commissioning:` 블록에서 읽습니다: 공장 자격증명, 설정할
비밀번호(`12#qweASD`, `accounts.secureadmin.password`와 일치해야 함), 관리
주소, 껐다 켤 포트 범위. 관리자 권한으로 실행할 수 없으면 `--skip-scan`을
붙이세요. 결과는 `reports/commission.json`에 남습니다.

### 실행

두 저장소 전체를, 올바른 순서로:

```cmd
venv\Scripts\python.exe scripts\run_secfunc.py
venv\Scripts\python.exe scripts\run_secfunc.py --list          # 실행 계획 보기
venv\Scripts\python.exe scripts\run_secfunc.py --skip-console  # 콘솔 케이블 미연결 시
venv\Scripts\python.exe scripts\run_secfunc.py --phase switch-ssh
```

또는 스위트를 하나씩:

```cmd
venv\Scripts\switchtest run --device admin       --suite suites\secfunc_all_ssh.yaml
venv\Scripts\switchtest run --device lowpriv     --suite suites\secfunc_lowpriv.yaml
venv\Scripts\switchtest run --device secureadmin --suite suites\secfunc_console.yaml
```

`--json reports\out.json`, `--junit reports\out.xml`, `--fail-fast`,
`--dry-run`(YAML만 검증하고 아무것도 건드리지 않음) 옵션을 추가할 수
있습니다.

#### 왜 이 순서로 실행하는가

이 러너는 두 도구를 단순히 순서대로 호출하는 것이 아닙니다. 세 가지
제약이 순서를 결정하며, 이를 어기면 스위치와 무관한 실패가 발생합니다:

1. **일부 점검은 의도적으로 스위치를 망가뜨립니다.** TC-SM-41B는 모든 IP
   서비스를 끄고, TC-IA-134는 이 머신의 IP를 차단합니다. 네트워크로만
   접근 가능한 항목은 반드시 먼저 끝나야 합니다.
2. **시리얼 케이블은 하나뿐입니다.** 두 저장소 모두 이를 사용하려 하므로,
   해당 단계들은 절대 겹치지 않습니다 — 이 때문에 어떤 것도 병렬로
   실행되지 않습니다.
3. **계정은 스스로를 생성할 수 없습니다.** 저권한 점검은 러너가 사전에
   프로비저닝하고 이후(크래시가 나더라도) 제거하는 계정으로 로그인합니다.

| # | 단계 | 세션 | 하는 일 |
|---|---|---|---|
| 1 | `password-change` | 콘솔 → SSH → API → 브라우저 | 동일한 비밀번호 변경 정책을 네 가지 전송 방식 모두에서, 하나씩 순서대로 확인 |
| 2 | `switch-ssh` | SSH, `admin` | 25개 테스트케이스; 파괴적이지 않음 |
| 3 | `switch-lowpriv` | SSH, `lowpriv` | 감사(audit) 접근 제한 확인 |
| 4 | `api-network` | HTTPS + 브라우저 | WebView가 떠 있어야 하므로 6단계보다 먼저 실행 |
| 5 | `api-console` | HTTPS + 콘솔 | 이 호스트의 IP를 차단하고, 콘솔을 통해 해제 |
| 6 | `switch-console` | 시리얼, `secureadmin` | 비밀번호 이력, SNMP, 잠금, 서비스 비활성화, IP 차단 — 이 순서대로 |

1단계는 동일한 정책 점검을 콘솔, SSH, API, 브라우저 순서로 함께가 아니라
하나씩 실행합니다: 네 가지 모두 하나의 계정 비밀번호를 변경하려 하므로,
동시에 실행하면 충돌합니다. 시도하는 모든 비밀번호는 애초에 유효하지
않으므로 실제로 아무것도 바뀌지 않습니다. 진행 상황은 전송 방식별로
표시됩니다.

> **실행이 단계 도중 중단되면**, 스위치가 이 머신을 계속 차단 중이거나
> 서비스가 꺼진 상태로 남을 수 있습니다. 콘솔에서 복구하세요:
> `aaa switch-access banned-ip all release` 및
> `ip service ssh admin-state enable`

### 테스트케이스

#### `suites/password_change_policy.yaml` — 네 가지 전송 방식 모두 (테스트케이스 1개 × 4)

`TC-IA-123`(비밀번호 변경 정책: 유효하지 않은 비밀번호는 모두 거부되어야
함)을 콘솔, SSH 순으로 실행한 뒤 — API 저장소에서 — API와 브라우저로
실행합니다. 통합 실행의 1단계입니다.

#### `suites/secfunc_all_ssh.yaml` — SSH, `admin` (17개)

| ID | 이름 |
|---|---|
| `TC-IA-121` | 안전한 비밀번호 정책 적용 |
| `TC-IA-122` | 신규 계정 생성 시 비밀번호 정책 적용 |
| `TC-IA-131` | 인증 실패 잠금 임계값 |
| `TC-IA-132` | 설정 가능한 잠금 지속시간 |
| `TC-IA-151` | 비밀번호 저장 시 취약한 암호 알고리즘 거부 |
| `TC-FC-312` | IEEE 802.1Q VLAN 태깅 |
| `TC-SM-41` | 원격 서비스 활성화/비활성화 |
| `TC-SM-441` | 펌웨어 버전 표시 |
| `TC-SM-442` | 펌웨어 해시 검증 |
| `TC-SM-461` | 세션 비활성 타임아웃 |
| `TC-ST-513` | 요청 시 하드웨어/프로세스 자체 테스트 |
| `TC-DP-711` | 원격 접속 암호화 채널 |
| `TC-DP-712` | TLS 기반 Syslog |
| `TC-DP-713` | WebView TLS 핸드셰이크가 TLS 1.2로 협상됨 — `capture_interface` 필요 |
| `TC-DP-716` | TLS 1.2 이상 |
| `TC-DP-717` | SSH v2 지원 |
| `TC-AU-842` | 외부 로그 서버로 감사 데이터 내보내기 |

여기에는 `show log swlog`를 읽는 시험이 없습니다. 이 명령은 secureadmin
전용이라 `admin` 계정으로는 세션이 끊길 뿐이며, swlog를 증거로 삼아야 하는
여덟 개는 아래 콘솔 스위트에 있습니다.

#### `suites/secfunc_lowpriv.yaml` — SSH, `lowpriv` (1개)

| ID | 이름 |
|---|---|
| `TC-AU-841` | 감사 데이터 접근 제한(저권한 계정) |

swlog를 **읽을 수 없다는 것**이 요점인 유일한 시험입니다 — 거부되는 것이 곧
성공 조건입니다. 아래 여덟 개와 혼동하지 마세요. 그쪽은 정반대로 swlog를
읽을 수 있어야 성립합니다.

#### `suites/secfunc_console.yaml` — 시리얼 콘솔, `secureadmin` (14개)

두 가지 이유 중 하나로 여기 모입니다: 이 머신을 네트워크에서 끊어버리거나
(그래서 대역 외 세션만이 검증과 복구를 할 수 있음), `show log swlog`를 읽어야
하거나(이 명령은 `secureadmin`만 가능).

순서가 중요합니다. 파괴적인 항목이 마지막이며 그대로 두어야 합니다.

| ID | 이름 | 콘솔인 이유 |
|---|---|---|
| `TC-IA-124` | 비밀번호 이력이 최근 비밀번호 재사용을 방지 | 전역 설정 |
| `TC-FC-311` | IP 기반 ACL 정책 설정 | swlog |
| `TC-SM-42` | SNMPv3 계정과 트랩 스테이션 생성 및 감사 | swlog |
| `TC-SM-43` | SNMPv3 get/set이 읽기/쓰기 계정에서는 동작, 읽기 전용 계정에서는 거부 | swlog |
| `TC-ST-511` | 부팅 시 하드웨어 자체 테스트 | swlog |
| `TC-ST-512` | 부팅 시 프로세스 자체 테스트 | swlog |
| `TC-ST-521` | 부팅 시 펌웨어 이미지 무결성 검사 | swlog |
| `TC-ST-523` | 백업/복원 시 설정 파일 무결성 검사 | swlog |
| `TC-AU-811` | 감사 데이터 생성 | swlog |
| `TC-AU-821` | 감사 데이터 필수 필드 | swlog |
| `TC-AU-831` | 임계값 초과 시 감사 기록 덮어쓰기 | swlog |
| `TC-IA-133` | SSH 잠금이 3회 실패 후 실제로 발동 | 계정을 잠금 |
| `TC-SM-41B` | 모든 IP 서비스 비활성화 시 실제로 모든 네트워크 관리 차단 | 네트워크 차단 |
| `TC-IA-134` | SSH IP 차단이 IP 잠금 임계값에서 실제로 발동 | 이 호스트를 차단 |

> **알려진 펌웨어 버그 — `TC-AU-811`은 실패하는 것이 정상입니다.** "펌웨어
> 업데이트" 검증이 swlog에서 `AOS upgrade or downgrade complete`를 찾는데, 이
> 펌웨어는 실제로 업그레이드를 수행해도 그 기록을 남기지 않습니다. 이 실패
> 자체가 발견 사항이므로, 검증을 완화해 통과시키지 말고 그대로 두세요. 나머지
> 네 검증(인증 성공/실패, 무결성, 서비스 활성화/비활성화)은 통과합니다.

> **`TC-IA-124`는 `admin` 계정의 현재 비밀번호가 `$test_password`와 같다고
> 가정합니다** — 재사용 케이스가 그 값으로 변경을 시도하기 때문입니다.
> 실제로는 비밀번호를 바꾸지 않습니다 — 거부되는 것이 곧 성공 조건이라
> 복원할 것 자체가 없습니다. `admin` 비밀번호가 다르다면 이 항목을
> 제외하거나(`--phase`에서 `switch-console` 제외, 또는 `--tag` 사용) 값을
> 맞추세요.

#### API 및 WebView 전송 방식 (`omniswitch_api_poc`)

HTTPS API와 실제 브라우저를 통한 동일한 동작 검증 — 비밀번호 정책, 계정
잠금, IP 차단, 메뉴 표시. 해당 저장소의 README를 참고하세요. 위의
`password-change`, `api-network`, `api-console` 단계에서 실행됩니다.

#### 기타 스위트

`suites/cis_smoke.yaml`(CIS 정렬 관리 강화), 그리고 `suites/smoke.yaml`과
번호가 매겨진 `suite1/3/4/5/7/8.yaml` 그룹들 — 동일한 secfunc
테스트케이스를 요구사항 섹션별로 나눈 것입니다.

### 테스트케이스 작성

테스트케이스는 `setup` → `validations` → `cleanup` 구조입니다. 검증 타입:
`contains`, `not_contains`, `regex`, `equals`, `ping`, `port_closed`,
`port_scan_closed`, `web_unreachable`, `web_reachable`, `api_unreachable`,
`tls_version`, `tcp_blocked`, `snmp_get`, `snmp_set`, `snmp_denied`.

기존 테스트케이스가 따르는 두 가지 규칙:

- **랩 환경의 값을 하드코딩하지 않습니다.** `$host`, `$station_ip`,
  `$system_name`, `$test_password`, `$<role>_user`, `$baseline_*`를
  사용하세요 — `switchtest show-config`가 전체 목록을 보여줍니다. 여덟 개
  테스트케이스에 독립적으로 박아 넣은 숫자는 언젠가 서로 어긋나게 되는
  숫자입니다.
- **setup이 바꾼 것은 cleanup이 반드시 복원합니다** — 리터럴 값이 아니라
  `$baseline_*` 값으로. 테스트케이스가 필요로 하는 계정은 그
  테스트케이스가 생성하고 삭제합니다.

```cmd
venv\Scripts\switchtest validate-testcase testcases\secfunc\check_ip_service.yaml
venv\Scripts\switchtest validate-suite suites\secfunc_all_ssh.yaml
venv\Scripts\python.exe -m pytest
```
