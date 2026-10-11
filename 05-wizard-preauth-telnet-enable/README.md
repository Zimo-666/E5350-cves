# CVE-TBD: Linksys E5350 Pre-Authentication Activation of Hidden Telnet Service (System/set_telnet) in Factory State

## Affected Product

- Vendor: Linksys
- Product: E5350
- Firmware: v1.0.00.037 (latest and last release; the product is end-of-life)
- Component: `httpd` gozila action `System/set_telnet` + librc.so `start_telnet` service

## Summary

A missing-authentication vulnerability was discovered in Linksys E5350
firmware v1.0.00.037. While the router is in factory/setup-wizard state
(`wizard_finish` not set), an unauthenticated remote attacker can enable
and start the device's **hidden telnet service** by posting
`submit_button=System&submit_type=set_telnet&telnet_enable=1` to the
pre-auth-reachable `/wizard/apply.cgi` dispatcher. The telnet service is
not exposed in the normal web UI flow and constitutes a dormant
debug/management interface that the owner never sees being activated.

## Vulnerability Type / CWE

- CWE-306: Missing Authentication for Critical Function
- CWE-489: Active Debug Code (dormant remote-access service activatable via
  the production web interface)

## Root Cause

- gozila action table (`httpd`, 0x496eb8) entry `System/set_telnet` →
  handler 0x42e16c executes
  `nvram_set_value("telnet_enable", get_cgi("telnet_enable"))` with no
  validation, and is dispatched through the same pre-auth
  `/wizard/apply.cgi` path described in companion filing
  01-wizard-preauth-command-injection (mime handler table entry 18, shared
  dispatcher, wizard-state whitelist).
- librc.so `start_telnet` (0x12adc): if `telnet_enable == "1"`, runs
  `system("killall -9 telnetd")` then `system("telnetd")`.
- The service trigger is `killall -HUP nvram_daemon` → SIGHUP handler =
  `start_single_service()` (nvram_daemon main @ 0x400cb0).

## Proof of Concept (non-destructive)

Precondition: router in factory/wizard state. **No credentials, no session.**

```
POST /wizard/apply.cgi HTTP/1.1
Host: <ROUTER_IP>
Content-Type: application/x-www-form-urlencoded

submit_button=System&submit_type=set_telnet&change_action=gozila_cgi&telnet_enable=1
```

Observed on rehosted firmware (QEMU user-mode, wizard_finish=0):

- `HTTP 200`; NVRAM store log: `SET action_service=set_telnet`,
  `SET telnet_enable=1`.
- Syscall trace of the service daemon after the SIGHUP trigger:
  `execve("/bin/sh",{"sh","-c","killall -9 telnetd 1>/dev/console 2>&1",NULL})`
  followed by
  `execve("/bin/sh",{"sh","-c","telnetd 1>/dev/console 2>&1",NULL})`

Honesty note: in the emulated rootfs `/usr/sbin/telnetd` is a 0-byte
extraction stub, so the post-activation login behavior was **not**
observable in the lab; on stock hardware `telnetd` is a busybox-style
daemon. The firmware ships no `/etc/passwd` template (it is created at boot
from NVRAM), so in factory state — before any admin password exists — the
resulting shell is expected to be unauthenticated or trivially
authenticated as root. **This final step requires on-hardware confirmation
and is stated here conservatively**; it is not reflected in the score.

## Impact

- **Demonstrated:** unauthenticated remote activation of a dormant
  remote-access service during the setup window — the device's attack
  surface is expanded without the owner's knowledge or consent, and the
  change persists in NVRAM.
- **Expected but not demonstrated:** on physical hardware, an
  unauthenticated or trivially authenticated root shell over telnet during
  the factory window (see honesty note above). Even taken alone, covert
  activation of a remote shell service on a network gateway is a
  security-relevant configuration change.

## Non-duplication

No existing CVE covers pre-auth telnet activation on Linksys E5350/E5400/
E5450. The closest record, CVE-2025-52692 (Linksys E9450-SG), enables
telnet via a URL-parsing authentication bypass — a different mechanism on a
different product and codebase. The only existing E5350 CVE is
CVE-2022-35572 (information disclosure, unrelated).

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` — **5.4 (Medium)**

(conservative: scored for unauthenticated activation of a hidden
remote-access service only; the expected unauthenticated root shell is not
counted pending hardware confirmation)

## Discovery

- Date: 2026-10-11
- Method: static reverse engineering (Ghidra) + dynamic verification on
  rehosted firmware (QEMU user-mode) with syscall-level runtime evidence
- Researcher: Zimo-666

## Timeline

- 2026-10-11: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
