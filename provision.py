import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from textwrap import dedent


def parse_args() -> argparse.Namespace:
    login = getpass.getuser()
    home = Path.home()
    parser = argparse.ArgumentParser(
        description="Provision a Hetzner Cloud server via the Hetzner API.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--name", default="devpush", help="Hetzner server name")
    parser.add_argument("--location", default="hil", help="Hetzner location slug")
    parser.add_argument("--type", dest="server_type", default="cpx31", help="Hetzner server type")
    parser.add_argument("--image", default="ubuntu-24.04", help="Base image slug")
    parser.add_argument("--user", default=login, help="Remote Linux user to create")
    parser.add_argument(
        "--pubkey",
        default=str(default_pubkey_path(home)),
        help="Public key to inject via cloud-init",
    )
    parser.add_argument(
        "--no-pubkey",
        action="store_true",
        help="Skip injecting a public key via cloud-init",
    )
    parser.add_argument(
        "--ssh-key-name",
        action="append",
        dest="ssh_key_names",
        help="Existing Hetzner SSH key name/ID to attach (repeatable)",
    )
    parser.add_argument(
        "--firewall",
        help="Attach an existing Hetzner firewall by name or ID",
    )
    parser.add_argument(
        "--no-harden",
        action="store_true",
        help="Skip hardening (default is hardened)",
    )
    parser.add_argument(
        "--token",
        help="Hetzner API token (or set HCLOUD_TOKEN)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the computed payload and cloud-init, then exit",
    )
    return parser.parse_args()


def default_pubkey_path(home: Path) -> Path:
    candidates = ["id_ed25519.pub", "id_rsa.pub"]
    ssh_dir = home / ".ssh"
    for name in candidates:
        path = ssh_dir / name
        if path.exists():
            return path
    return ssh_dir / "id_ed25519.pub"


def read_pubkey(path_str: str) -> str:
    path = Path(path_str).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Public key not found at {path}")
    data = path.read_text(encoding="utf-8").strip()
    if not data:
        raise ValueError(f"Public key file {path} is empty")
    return data


def read_harden_script() -> str | None:
    script_path = Path(__file__).parent / "harden.sh"
    if script_path.exists():
        return script_path.read_text(encoding="utf-8")
    return None


def build_cloud_init(user: str, pubkey: str | None, harden: bool) -> str:
    packages: list[str] = []
    write_files: list[dict[str, str]] = []
    runcmd: list[str] = []

    ssh_authorized_keys = []
    if pubkey:
        ssh_authorized_keys.append(pubkey)

    copy_root_key_cmd = None
    if not pubkey:
        copy_root_key_cmd = (
            dedent(
                f"""\
                if [ -f /root/.ssh/authorized_keys ]; then
                  install -d -m 700 -o {user} -g {user} /home/{user}/.ssh
                  cp /root/.ssh/authorized_keys /home/{user}/.ssh/authorized_keys
                  chown {user}:{user} /home/{user}/.ssh/authorized_keys
                  chmod 600 /home/{user}/.ssh/authorized_keys
                fi
                """
            )
            .strip()
            .replace("\n", " ")
        )

    if harden:
        ssh_pub_flag = f"--ssh-pub '{pubkey}'" if pubkey else ""
        harden_script = read_harden_script()
        if harden_script:
            write_files.append(
                {
                    "path": "/usr/local/bin/harden.sh",
                    "permissions": "0755",
                    "owner": "root:root",
                    "content": harden_script,
                }
            )
            runcmd.append(
                " ".join(
                    arg
                    for arg in [
                        "/usr/local/bin/harden.sh",
                        "--ssh",
                        f"--user {user}",
                        ssh_pub_flag,
                    ]
                    if arg
                )
            )
        else:
            packages.extend(["ufw", "fail2ban", "unattended-upgrades"])
            write_files.append(
                {
                    "path": "/etc/ssh/sshd_config.d/99-hardening.conf",
                    "permissions": "0644",
                    "owner": "root:root",
                    "content": dedent(
                        """\
                        PermitRootLogin no
                        PasswordAuthentication no
                        """
                    ).strip(),
                }
            )
            runcmd.extend(
                [
                    "ufw default deny incoming",
                    "ufw default allow outgoing",
                    "ufw allow OpenSSH",
                    "ufw allow 80",
                    "ufw allow 443",
                    "yes | ufw enable",
                    "systemctl enable --now fail2ban",
                    "systemctl enable --now unattended-upgrades",
                    "systemctl restart ssh",
                ]
            )

    if copy_root_key_cmd and copy_root_key_cmd not in runcmd:
        runcmd.insert(0, copy_root_key_cmd)

    lines: list[str] = [
        "#cloud-config",
        "users:",
        f"  - name: {user}",
        "    groups: sudo",
        "    shell: /bin/bash",
        "    sudo: ['ALL=(ALL) NOPASSWD:ALL']",
        "    lock_passwd: true",
    ]

    if ssh_authorized_keys:
        lines.append("    ssh_authorized_keys:")
        lines.extend([f"      - {key}" for key in ssh_authorized_keys])

    lines.extend(
        [
            "disable_root: true",
            "ssh_pwauth: false",
            "package_update: true",
            "package_upgrade: true",
        ]
    )

    if packages:
        lines.append("packages:")
        lines.extend([f"  - {pkg}" for pkg in packages])

    if write_files:
        lines.append("write_files:")
        for wf in write_files:
            lines.extend(
                [
                    f"  - path: {wf['path']}",
                    f"    permissions: '{wf['permissions']}'",
                    f"    owner: {wf['owner']}",
                    "    content: |",
                ]
            )
            lines.extend([f"      {line}" for line in wf["content"].splitlines()])

    if runcmd:
        lines.append("runcmd:")
        lines.extend([f"  - {cmd}" for cmd in runcmd])

    return "\n".join(lines)


def api_request(method: str, path: str, token: str, payload: dict | None = None) -> dict:
    url = f"https://api.hetzner.cloud/v1{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API {method} {path} failed: {exc.code} {body}") from exc


def create_server(args: argparse.Namespace, cloud_init: str, token: str):
    def maybe_int(val: str):
        try:
            return int(val)
        except (TypeError, ValueError):
            return val

    payload: dict = {
        "name": args.name,
        "server_type": args.server_type,
        "image": args.image,
        "location": args.location,
        "user_data": cloud_init,
        "labels": {"managed-by": "devpush"},
    }

    ssh_keys = [maybe_int(k) for k in args.ssh_key_names or []]
    if ssh_keys:
        payload["ssh_keys"] = ssh_keys

    if args.firewall:
        payload["firewalls"] = [{"firewall": maybe_int(args.firewall)}]

    if args.dry_run:
        print("Computed cloud-init:\n")
        print(cloud_init)
        print("\nPlanned API call payload:\n")
        print(json.dumps(payload, indent=2))
        return

    response = api_request("POST", "/servers", token, payload)
    server = response.get("server") or {}
    print(json.dumps(server, indent=2))


def main():
    args = parse_args()

    token = args.token or os.environ.get("HCLOUD_TOKEN")
    if not token:
        try:
            token = getpass.getpass("Hetzner API token (input hidden): ").strip()
        except (EOFError, KeyboardInterrupt):
            token = ""
    if not token:
        print(
            "error: provide Hetzner token via prompt, --token, or HCLOUD_TOKEN",
            file=sys.stderr,
        )
        sys.exit(1)

    pubkey = None
    if not args.no_pubkey:
        try:
            pubkey = read_pubkey(args.pubkey)
        except FileNotFoundError:
            if not args.ssh_key_names:
                pasted = input(
                    "Public key file not found. Paste a public key (or leave blank to skip): "
                ).strip()
                if pasted:
                    pubkey = pasted
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(1)

    if not pubkey and not args.ssh_key_names:
        print(
            "error: no SSH key provided. Specify --ssh-key-name or provide a public key to avoid lockout.",
            file=sys.stderr,
        )
        sys.exit(1)

    harden = not args.no_harden
    cloud_init = build_cloud_init(args.user, pubkey, harden)
    create_server(args, cloud_init, token)


if __name__ == "__main__":
    main()
