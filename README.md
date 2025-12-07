# /dev/push Hetzner provisioning

Minimal Python (stdlib-only) helper to create a Hetzner Cloud server via the API. It sets up a non-root sudo user, disables root/password SSH, injects SSH keys, and runs a hardening script on first boot.

## Quick start

```bash
# optional: export HCLOUD_TOKEN=your-token
python provision.py
```

This will:
- Create `devpush` (type `cpx31`, location `hil`, image `ubuntu-24.04`)
- Create your user (defaults to your local login) with passwordless sudo; disable root/password SSH
- Inject your SSH key (auto-detected) or copy the Hetzner key attached to root when using `--ssh-key-name`
- Run `harden.sh` on first boot (UFW, fail2ban, unattended upgrades, SSH hardening) — default on

## Requirements

- Python 3.10+
- Hetzner API token (see [Getting a Token](#getting-a-token) below)
- At least one SSH key: `--pubkey` or `--ssh-key-name`

## Getting a Token

1. **Create a Hetzner Cloud account** (if you don't have one):
   - Sign up at https://www.hetzner.com/cloud

2. **Create a project**:
   - Log in to https://console.hetzner.cloud/
   - Click "New Project" and give it a name (e.g., "devpush")

3. **Generate an API token**:
   - In your project, go to "Security" → "API Tokens"
   - Click "Generate API Token"
   - Give it a name (e.g., "devpush-provisioning")
   - Select permissions: "Read & Write" (or at minimum: "Servers" read/write)
   - Copy the token immediately (it's only shown once)

4. **Use the token**:
   - Set `HCLOUD_TOKEN` environment variable: `export HCLOUD_TOKEN=your-token`
   - Or pass via `--token` flag: `python provision.py --token your-token`
   - Or enter it when prompted (input is hidden)

## Options

- `--name` server name (default `devpush`)
- `--type` server type (default `cpx31`)
- `--location` location (default `hil`)
- `--image` image slug (default `ubuntu-24.04`)
- `--user` remote username (default: your local login)
- `--pubkey` path to SSH public key (auto-detected)
- `--ssh-key-name` Hetzner SSH key name/ID to attach (repeatable, uses Hetzner key seeded to root)
- `--firewall` firewall ID to attach
- `--no-harden` skip bundled `harden.sh` (default is hardened)
- `--token` Hetzner API token (or `HCLOUD_TOKEN`)
- `--dry-run` print cloud-init and payload instead of creating
