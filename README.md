# Linksys E5350 v1.0.00.037 — Vulnerability Disclosure Package

Five security vulnerabilities discovered in Linksys E5350 firmware
v1.0.00.037 (the latest and last release; the product is end-of-life) via
firmware rehosting (QEMU user-mode), static reverse engineering (Ghidra),
and dynamic PoC verification in an isolated, authorized research
environment.

Each subdirectory is a standalone disclosure document referenced as the
public advisory URL of a CVE request (VulDB CNA). CVE IDs are placeholders
until assigned.

The E5350 web stack is a CyberTAN-derived `httpd` written in C (not the
lighttpd/Lua stack of the E5600 series). Four of the five issues are
reachable **without any credentials** while the router is in its
factory/setup-wizard state (`wizard_finish != 1`: out-of-box, or after a
factory reset, before the owner completes initial setup).

| Dir | Vulnerability | Type | CWE | Auth | CVSS 3.1 (proposed) |
|-----|---------------|------|-----|------|---------------------|
| 01-wizard-preauth-command-injection | /wizard/apply.cgi exposes Diagnostics ping_ip/traceroute_ip command injection pre-auth in factory state | Command Injection | CWE-306 + CWE-78 | None (factory state) | 8.8 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 02-empty-admin-password-auth-bypass | Wizard accepts empty admin password; wizard_finish+close_session+empty http_passwd = permanent full auth bypass | Auth Bypass | CWE-258 / CWE-306 | None (initiated in factory state) | 8.8 AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 03-diagnostics-command-injection | Diagnostics ping_ip and traceroute_ip stored unsanitized, executed via system() | Command Injection | CWE-78 | Authenticated | 6.8 AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H |
| 04-wan-dns-stack-overflow | wan_dns handler: four unbounded strcat() into a 20-byte stack buffer; crash verified pre-auth and post-auth | Buffer Overflow | CWE-121 | None (factory state) / Authenticated | 6.5 AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |
| 05-wizard-preauth-telnet-enable | System/set_telnet starts hidden telnetd pre-auth in factory state | Hidden Service Activation | CWE-306 / CWE-489 | None (factory state) | 5.4 AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (conservative) |

Separately verified: **CVE-2022-35572** (pre-auth information disclosure in
`/SysInfo.htm`) is **still present and unpatched** in v1.0.00.037 — WPA
passphrase, WPS PIN and serial number are readable without any session.
That issue is an existing CVE and is NOT re-filed here; it is mentioned
only as context for the weak pre-auth attack-surface review of this
codebase.

## Submission checklist (per vulnerability)

1. This public repo is the advisory reference; each subdirectory README.md
   is the disclosure document for one CVE request.
2. VulDB: https://vuldb.com/?submit — paste Description, CWE, CVSS, and the
   subdirectory URL as Advisory reference. Request a CVE per issue.
3. After the CVE ID is assigned, replace `CVE-TBD` in the subdirectory
   README title and update the VulDB entry.
4. Vendor notification (Linksys security/support channels) is sent by the
   researcher in parallel; Linksys historically does not respond to such
   reports (cf. CVE-2025-9146), which does not block CVE assignment.

## Notes

- Replace `<ROUTER_IP>` placeholders with the target address when
  reproducing.
- All PoCs are non-destructive: marker files under /tmp only, plus one
  demonstrated daemon crash (04); no configuration changes, no flashing,
  no persistence.
- Discovery date: 2026-10-11. Product status: end-of-life (no fix
  expected); vulnerabilities in EOL products remain valid CVE candidates.
- Researcher: Zimo-666
