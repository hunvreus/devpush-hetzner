#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

[[ $EUID -eq 0 ]] || { printf "harden.sh must be run as root (sudo).\n" >&2; exit 2; }

usage() {
  cat <<USG
Usage: harden.sh [--ssh] [--user <username>] [--ssh-pub <key_or_path>]

Applies basic server hardening:
- installs ufw, fail2ban, unattended-upgrades
- enables fail2ban and unattended-upgrades
- optionally hardens SSH (disable root login, disable password auth) with --ssh
- configures UFW to allow 22,80,443 and enables it

  --ssh                  Also apply SSH hardening (see below)
  --user USERNAME        Username for SSH key setup (auto-detected if not provided)
  --ssh-pub KEY|PATH     Public key content or file to seed authorized_keys if missing
  -h, --help             Show this help
USG
  exit 0
}

user=""; ssh_pub=""; with_ssh=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh) with_ssh=1; shift ;;
    --user) user="$2"; shift 2 ;;
    --ssh-pub) ssh_pub="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if ! command -v apt-get >/dev/null; then
  echo "error: apt-get not found (only Ubuntu/Debian supported)" >&2
  exit 4
fi

if ((with_ssh==1)); then
  if [[ -z "$user" ]]; then
    user=$(logname 2>/dev/null || echo "${SUDO_USER:-}")
    if [[ -z "$user" ]]; then
      user=$(who am i | awk '{print $1}' || echo "")
    fi
    if [[ -z "$user" ]] || [[ "$user" == "root" ]]; then
      for u in $(getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}'); do
        if [[ -d "/home/$u" ]]; then
          user="$u"
          break
        fi
      done
    fi
  fi
  if [[ -z "$user" ]] || [[ "$user" == "root" ]] || ! id -u "$user" >/dev/null 2>&1; then
    echo "error: Could not determine valid non-root user for SSH hardening" >&2
    exit 5
  fi
fi

if ((with_ssh==1)); then
  ak="/home/$user/.ssh/authorized_keys"
  if [[ -n "$ssh_pub" ]]; then
    install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
    if [[ -f "$ssh_pub" ]]; then
      cat "$ssh_pub" >> "$ak"
    else
      printf '%s\n' "$ssh_pub" >> "$ak"
    fi
    chown "$user:$user" "$ak"
    chmod 600 "$ak"
  fi

  if [[ ! -s "$ak" && -s /root/.ssh/authorized_keys ]]; then
    install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
    cat /root/.ssh/authorized_keys >> "$ak"
    chown "$user:$user" "$ak"
    chmod 600 "$ak"
  fi

  if [[ -f "$ak" ]]; then
    sort -u "$ak" -o "$ak"
    chown "$user:$user" "$ak"
    chmod 600 "$ak"
  fi

  if [[ ! -s "$ak" ]]; then
    echo "warning: SSH hardening requires a public key. Provide --ssh-pub <key|path> or ensure $ak exists and is non-empty." >&2
    exit 6
  fi
fi

echo "Installing security packages..."
for i in {1..5}; do
  if apt-get update -y && apt-get install -y ufw fail2ban unattended-upgrades; then
    break
  fi
  if [[ $i -eq 5 ]]; then
    echo "error: Failed to install packages after 5 attempts" >&2
    exit 1
  fi
  sleep 3
done

echo "Enabling services..."
systemctl enable --now fail2ban
systemctl enable --now unattended-upgrades

if ((with_ssh==1)); then
  echo "Hardening SSH..."
  if grep -q '^PermitRootLogin' /etc/ssh/sshd_config || grep -q '^#PermitRootLogin' /etc/ssh/sshd_config; then
    sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  else
    printf "PermitRootLogin no\n" >> /etc/ssh/sshd_config
  fi
  if grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || grep -q '^#PasswordAuthentication' /etc/ssh/sshd_config; then
    sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  else
    printf "PasswordAuthentication no\n" >> /etc/ssh/sshd_config
  fi
  if systemctl list-units --type=service --all | grep -q 'ssh.service'; then
    systemctl restart ssh
  elif systemctl list-units --type=service --all | grep -q 'sshd.service'; then
    systemctl restart sshd
  else
    echo "warning: Could not find ssh or sshd service" >&2
  fi
fi

echo "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22
ufw allow 80
ufw allow 443
yes | ufw enable

echo "Hardening complete. ✔"

