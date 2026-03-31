# `oc-hardened.sh`

Back to repo index: [`README.md`](../README.md)

`oc-hardened.sh` sets up a fresh Ubuntu 24.04 server with a safer default config, then runs OpenClaw as a dedicated sudo user.

## Quick Start

```bash
curl -fsSL https://sh.pew.dev/oc-hardened.sh | sudo bash
```

## What It Does

- Creates/reuses a user (default: `openclaw`) and adds sudo access
- Sets up SSH hardening (`PermitRootLogin no`, password auth off, key auth on)
- Configures UFW (SSH only by default)
- Installs/configures `fail2ban` and `unattended-upgrades`
- Runs OpenClaw install as the dedicated user
- Automatically switches to the dedicated user shell after OpenClaw onboarding so you can run pairing commands (unless `--no-switch-user` is set)

## Requirements

- Ubuntu `24.04`
- Run as root (`sudo`)
- You must have an SSH key for the target user, or for the invoking sudo user in `~/.ssh/authorized_keys`
- If the script is run directly as root (no sudo user context), it falls back to `/root/.ssh/authorized_keys`
- If no key exists in the applicable locations, the script stops before SSH hardening (to avoid lockout)

## Common Commands

Default:

```bash
curl -fsSL https://sh.pew.dev/oc-hardened.sh | sudo bash
```

Custom user + SSH port:

```bash
curl -fsSL https://sh.pew.dev/oc-hardened.sh | sudo bash -s -- \
  --user myadmin \
  --ssh-port 2222
```

Pass your public key directly:

```bash
curl -fsSL https://sh.pew.dev/oc-hardened.sh | sudo bash -s -- \
  --user myadmin \
  --authorized-key "ssh-ed25519 AAAA... you@laptop"
```

Allow web ports (`80`, `443`):

```bash
curl -fsSL https://sh.pew.dev/oc-hardened.sh | sudo bash -s -- --allow-web-ports
```

Dry run:

```bash
curl -fsSL https://sh.pew.dev/oc-hardened.sh | sudo bash -s -- --dry-run
```

## Options

- `--user <name>` (default: `openclaw`)
- `--ssh-port <port>` (default: `22`)
- `--openclaw-cmd <cmd>` (default: `curl -fsSL https://openclaw.ai/install.sh | bash`)
- `--authorized-key <key>`
- `--skip-user-password` (no `passwd` prompt)
- `--no-switch-user` (do not auto-switch to the user shell at the end)
- `--allow-web-ports` (allow `80/tcp` and `443/tcp`)
- `--dry-run`
- `-h`, `--help`

## Notes

- OpenClaw setup runs once per user + command hash marker: `/var/lib/openclaw-bootstrap/openclaw_cmd.<user>.sha256`.
- Remove that marker file to force a re-run with the same command.
- `--authorized-key` must be a single valid OpenSSH public key line.
- Even when invoked with `curl ... | sudo bash`, the script uses `/dev/tty` for password prompts and the final user switch when available.
- In truly non-interactive environments (no `/dev/tty`), use `--skip-user-password`; switch users manually with `sudo -iu <user>`.

## Troubleshooting

If you see:

`ERROR: Failed to set password for '<user>' in non-interactive mode`

This means the script could not access an interactive TTY for `passwd` (for example, no `/dev/tty` in the current environment).

Use one of these:

Skip password setup (recommended for key-based SSH):

```bash
curl -fsSL https://sh.pew.dev/oc-hardened.sh | sudo bash -s -- --skip-user-password
```

Or run without piping so `passwd` can prompt normally:

```bash
curl -fsSLo /tmp/oc-hardened.sh https://sh.pew.dev/oc-hardened.sh
sudo bash /tmp/oc-hardened.sh
```

## Important

Before closing your current root session, confirm SSH login works for the dedicated user.
