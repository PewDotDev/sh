#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
TARGET_USER="openclaw"
SSH_PORT="22"
OPENCLAW_CMD='curl -fsSL https://openclaw.ai/install.sh | bash'
AUTHORIZED_KEY=""
ALLOW_WEB_PORTS=0
DRY_RUN=0
SET_USER_PASSWORD=1
AUTO_SWITCH_TO_USER=1
SYSTEMD_USER_RUNTIME_DIR=""
SYSTEMD_USER_BUS_ADDRESS=""
SYSTEMD_USER_SERVICES_READY=0

STATE_DIR="/var/lib/openclaw-bootstrap"
TEMP_NOSUDO_FILE="/etc/sudoers.d/90-openclaw-bootstrap-nopasswd"

SSH_CONFIG_FILE="/etc/ssh/sshd_config"
SSH_BACKUP_FILE="/etc/ssh/sshd_config.openclaw-backup"
SSH_HARDEN_FILE="/etc/ssh/sshd_config.d/00-openclaw-hardening.conf"
UNATTENDED_AUTO_UPGRADES_FILE="/etc/apt/apt.conf.d/20auto-upgrades"
FAIL2BAN_SSH_JAIL_FILE="/etc/fail2ban/jail.d/openclaw-sshd.local"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

usage() {
  cat <<USAGE
Usage: ${SCRIPT_NAME} [options]

Bootstrap and harden an Ubuntu 22.04 or above VPS, then run OpenClaw setup.

Options (all optional):
  --user <name>          Dedicated sudo user for OpenClaw (default: openclaw)
  --ssh-port <port>      SSH daemon port and UFW allow port (default: 22)
  --openclaw-cmd <cmd>   Command run as the dedicated user
                         (default: curl -fsSL https://openclaw.ai/install.sh | bash)
  --authorized-key <key> Optional SSH public key to add for --user
  --skip-user-password   Do not prompt for password; keep it disabled/locked
  --no-switch-user      Do not auto-switch to the dedicated user at the end
  --allow-web-ports      Also allow inbound 80/tcp and 443/tcp in UFW
  --dry-run              Print actions without making changes
  -h, --help             Show this help

Examples:
  curl -fsSL <url> | sudo bash
  curl -fsSL <url> | sudo bash -s -- --user myadmin --ssh-port 2222 --allow-web-ports
  curl -fsSL <url> | sudo bash -s -- --user myadmin --authorized-key "ssh-ed25519 AAAA... me@laptop"
USAGE
}

run_cmd() {
  if ((DRY_RUN)); then
    log "[dry-run] $*"
  else
    "$@"
  fi
}

run_shell() {
  local cmd="$1"
  if ((DRY_RUN)); then
    log "[dry-run] bash -lc '$cmd'"
  else
    bash -lc "$cmd"
  fi
}

parse_args() {
  while (($#)); do
    case "$1" in
      --user)
        [[ $# -ge 2 ]] || die "Missing value for --user"
        TARGET_USER="$2"
        shift 2
        ;;
      --ssh-port)
        [[ $# -ge 2 ]] || die "Missing value for --ssh-port"
        SSH_PORT="$2"
        shift 2
        ;;
      --openclaw-cmd)
        [[ $# -ge 2 ]] || die "Missing value for --openclaw-cmd"
        OPENCLAW_CMD="$2"
        shift 2
        ;;
      --authorized-key)
        [[ $# -ge 2 ]] || die "Missing value for --authorized-key"
        AUTHORIZED_KEY="$2"
        shift 2
        ;;
      --skip-user-password)
        SET_USER_PASSWORD=0
        shift
        ;;
      --no-switch-user)
        AUTO_SWITCH_TO_USER=0
        shift
        ;;
      --allow-web-ports)
        ALLOW_WEB_PORTS=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done
}

validate_ssh_public_key() {
  local key="$1"
  local key_type
  local key_blob
  local key_file

  key_type="$(printf '%s\n' "$key" | awk '{print $1}')"
  key_blob="$(printf '%s\n' "$key" | awk '{print $2}')"

  [[ -n "$key_type" && -n "$key_blob" ]] || return 1

  case "$key_type" in
    ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)
      ;;
    *)
      return 1
      ;;
  esac

  [[ "$key_blob" =~ ^[A-Za-z0-9+/]+=*$ ]] || return 1

  key_file="$(mktemp)"
  printf '%s\n' "$key" > "$key_file"
  if ! ssh-keygen -l -f "$key_file" >/dev/null 2>&1; then
    rm -f "$key_file"
    return 1
  fi
  rm -f "$key_file"

  return 0
}

validate_inputs() {
  [[ -n "$TARGET_USER" ]] || die "--user cannot be empty"
  [[ "$TARGET_USER" != "root" ]] || die "--user cannot be root"
  [[ "$TARGET_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Invalid --user: $TARGET_USER"

  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "--ssh-port must be a number"
  ((SSH_PORT >= 1 && SSH_PORT <= 65535)) || die "--ssh-port must be between 1 and 65535"

  [[ -n "${OPENCLAW_CMD// }" ]] || die "--openclaw-cmd cannot be empty"
  if [[ -n "$AUTHORIZED_KEY" ]]; then
    [[ -n "${AUTHORIZED_KEY// }" ]] || die "--authorized-key cannot be empty"
    [[ "$AUTHORIZED_KEY" != *$'\n'* ]] || die "--authorized-key must be a single line"
    command -v ssh-keygen >/dev/null 2>&1 || die "--authorized-key validation requires ssh-keygen"
    validate_ssh_public_key "$AUTHORIZED_KEY" || die "--authorized-key is not a valid SSH public key"
  fi
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root (for example: curl -fsSL <url> | sudo bash)"
  fi
}

validate_os() {
  [[ -f /etc/os-release ]] || die "Cannot detect OS. /etc/os-release is missing"
  # shellcheck disable=SC1091
  source /etc/os-release

  [[ "${ID:-}" == "ubuntu" ]] || die "Unsupported OS: ${ID:-unknown}. This script supports Ubuntu 22.04 or above"
  [[ -n "${VERSION_ID:-}" ]] || die "Cannot detect Ubuntu version from /etc/os-release"
  if ! dpkg --compare-versions "${VERSION_ID}" ge "22.04"; then
    die "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Use Ubuntu 22.04 or above"
  fi

  command -v apt-get >/dev/null 2>&1 || die "apt-get is required"
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
}

prepare_state_dir() {
  run_cmd mkdir -p "$STATE_DIR"
}

openclaw_marker_file() {
  printf '%s/openclaw_cmd.%s.sha256' "$STATE_DIR" "$TARGET_USER"
}

install_base_packages() {
  log "Installing required packages"
  export DEBIAN_FRONTEND=noninteractive
  run_cmd apt-get update
  run_cmd apt-get upgrade -y
  run_cmd apt-get install -y ufw fail2ban unattended-upgrades sudo curl ca-certificates openssh-server
}

ensure_target_user() {
  local user_home

  if id "$TARGET_USER" >/dev/null 2>&1; then
    log "User '$TARGET_USER' already exists"
  else
    log "Creating user '$TARGET_USER'"
    run_cmd adduser --disabled-password --gecos "" "$TARGET_USER" >/dev/null
  fi

  run_cmd usermod -aG sudo "$TARGET_USER" >/dev/null

  user_home="$(getent passwd "$TARGET_USER" | cut -d: -f6 || true)"
  if [[ -z "$user_home" ]] && ((DRY_RUN)); then
    user_home="/home/$TARGET_USER"
    log "[dry-run] assuming home directory for '$TARGET_USER' would be $user_home"
  fi
  [[ -n "$user_home" ]] || die "Unable to determine home directory for $TARGET_USER"
  printf '%s' "$user_home"
}

set_target_user_password_if_requested() {
  local password_prompt_mode="stdio"
  local tty_fd=""

  if ((SET_USER_PASSWORD)); then
    log "Setting password for '$TARGET_USER'"
    if ((DRY_RUN)); then
      log "[dry-run] would run: passwd $TARGET_USER"
    else
      if [[ ! -t 0 || ! -t 1 ]]; then
        if exec {tty_fd}<> /dev/tty; then
          password_prompt_mode="tty"
          log "Piped/non-interactive stdin detected; using /dev/tty for password prompts"
        else
          password_prompt_mode="none"
        fi
      fi

      if [[ "$password_prompt_mode" == "none" ]]; then
        die "Failed to set password for '$TARGET_USER' in non-interactive mode. Re-run with --skip-user-password or run script without piping"
      fi

      while true; do
        if [[ "$password_prompt_mode" == "tty" ]]; then
          if passwd "$TARGET_USER" <&"$tty_fd" >&"$tty_fd" 2>&1; then
            log "Password set for '$TARGET_USER'"
            break
          fi
        elif run_cmd passwd "$TARGET_USER"; then
          log "Password set for '$TARGET_USER'"
          break
        fi

        if [[ "$password_prompt_mode" == "tty" ]]; then
          log "Password update failed (for example, mismatch or policy). Please try again"
          continue
        fi

        if [[ ! -t 0 || ! -t 1 ]]; then
          die "Failed to set password for '$TARGET_USER' in non-interactive mode. Re-run with --skip-user-password or run script without piping"
        fi

        log "Password update failed (for example, mismatch or policy). Please try again"
      done

      if [[ -n "$tty_fd" ]]; then
        exec {tty_fd}>&-
      fi
    fi
  fi
}

ensure_target_authorized_keys() {
  local user_home="$1"
  local target_ssh_dir="${user_home}/.ssh"
  local target_auth_keys="${target_ssh_dir}/authorized_keys"
  local root_auth_keys="/root/.ssh/authorized_keys"
  local invoking_user="${SUDO_USER:-}"
  local invoking_user_home=""
  local invoking_user_auth_keys=""

  run_cmd install -d -m 700 -o "$TARGET_USER" -g "$TARGET_USER" "$target_ssh_dir"

  if [[ -L "$target_auth_keys" ]]; then
    die "Refusing to use symlinked authorized_keys path: $target_auth_keys"
  fi
  if [[ -e "$target_auth_keys" && ! -f "$target_auth_keys" ]]; then
    die "Refusing to use non-regular authorized_keys path: $target_auth_keys"
  fi

  if [[ -n "$AUTHORIZED_KEY" ]]; then
    if ((DRY_RUN)); then
      log "[dry-run] ensure provided --authorized-key is present in $target_auth_keys"
    else
      if [[ ! -f "$target_auth_keys" ]]; then
        run_cmd install -m 600 -o "$TARGET_USER" -g "$TARGET_USER" /dev/null "$target_auth_keys"
      fi
      if grep -Fxq -- "$AUTHORIZED_KEY" "$target_auth_keys"; then
        log "Provided --authorized-key already exists for '$TARGET_USER'"
      else
        printf '%s\n' "$AUTHORIZED_KEY" >> "$target_auth_keys"
        log "Added provided --authorized-key for '$TARGET_USER'"
      fi
    fi
  fi

  if [[ -s "$target_auth_keys" ]]; then
    log "Found SSH key(s) for '$TARGET_USER'"
  else
    if [[ -n "$invoking_user" && "$invoking_user" != "root" ]]; then
      invoking_user_home="$(getent passwd "$invoking_user" | cut -d: -f6 || true)"
      if [[ -n "$invoking_user_home" ]]; then
        invoking_user_auth_keys="${invoking_user_home}/.ssh/authorized_keys"
      fi
    fi

    if [[ -n "$invoking_user_auth_keys" && -s "$invoking_user_auth_keys" ]]; then
      log "Copying $invoking_user authorized_keys to '$TARGET_USER' to prevent lockout"
      run_cmd cp "$invoking_user_auth_keys" "$target_auth_keys"
      run_cmd chown "$TARGET_USER:$TARGET_USER" "$target_auth_keys"
      run_cmd chmod 600 "$target_auth_keys"
    elif [[ -z "$invoking_user_auth_keys" && -s "$root_auth_keys" ]]; then
      log "Copying root authorized_keys to '$TARGET_USER' to prevent lockout"
      run_cmd cp "$root_auth_keys" "$target_auth_keys"
      run_cmd chown "$TARGET_USER:$TARGET_USER" "$target_auth_keys"
      run_cmd chmod 600 "$target_auth_keys"
    elif ((DRY_RUN)); then
      if [[ -n "$invoking_user_auth_keys" ]]; then
        log "[dry-run] no SSH keys found yet for '$TARGET_USER' in target or $invoking_user_auth_keys; non-dry-run would abort before SSH hardening"
      else
        log "[dry-run] no SSH keys found yet for '$TARGET_USER' in target or root; non-dry-run would abort before SSH hardening"
      fi
    else
      if [[ -n "$invoking_user_auth_keys" ]]; then
        die "No SSH keys found for '$TARGET_USER'. Checked $target_auth_keys and $invoking_user_auth_keys. Aborting before SSH hardening"
      else
        die "No SSH keys found for '$TARGET_USER'. Checked $target_auth_keys and $root_auth_keys. Aborting before SSH hardening"
      fi
    fi
  fi

  run_cmd chown "$TARGET_USER:$TARGET_USER" "$target_auth_keys"
  run_cmd chmod 600 "$target_auth_keys"

  if ((!DRY_RUN)) && [[ ! -s "$target_auth_keys" ]]; then
    die "authorized_keys for '$TARGET_USER' is empty. Aborting before SSH hardening"
  fi
}

backup_ssh_config_once() {
  [[ -f "$SSH_CONFIG_FILE" ]] || die "Missing SSH config: $SSH_CONFIG_FILE"

  if [[ -f "$SSH_BACKUP_FILE" ]]; then
    log "SSH backup already exists at $SSH_BACKUP_FILE"
  else
    log "Backing up SSH config to $SSH_BACKUP_FILE"
    run_cmd cp "$SSH_CONFIG_FILE" "$SSH_BACKUP_FILE"
  fi

  run_cmd mkdir -p "$(dirname "$SSH_HARDEN_FILE")"
}

write_ssh_hardening_config() {
  log "Writing SSH hardening config to $SSH_HARDEN_FILE"

  if ((DRY_RUN)); then
    log "[dry-run] write file '$SSH_HARDEN_FILE' with Port $SSH_PORT, PermitRootLogin no, PasswordAuthentication no, KbdInteractiveAuthentication no, ChallengeResponseAuthentication no, PubkeyAuthentication yes"
    return
  fi

  cat > "$SSH_HARDEN_FILE" <<EOF
# Managed by OpenClaw VPS bootstrap script.
# Keep this file first in include order so these values take precedence.
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
EOF
}

reload_ssh_service() {
  # Some cloud images do not pre-create this runtime dir until ssh.service starts.
  # Ensure it exists so `sshd -t` does not fail with "Missing privilege separation directory".
  run_cmd install -d -m 755 -o root -g root /run/sshd
  run_cmd sshd -t
  if run_shell "systemctl reload ssh || systemctl restart ssh || systemctl reload sshd || systemctl restart sshd"; then
    return 0
  fi

  die "Failed to reload/restart SSH daemon via systemctl (tried ssh and sshd services)"
}

pre_allow_ssh_port_in_firewall() {
  log "Ensuring UFW allows ${SSH_PORT}/tcp before SSH service reload"
  run_cmd ufw allow "${SSH_PORT}/tcp"
}

remove_ufw_allow_rule_if_present() {
  local port="$1"
  local rule_number=""

  if ((DRY_RUN)); then
    log "[dry-run] remove ufw allow ${port}/tcp (IPv4 and IPv6) if present"
    return
  fi

  while true; do
    rule_number="$(
      ufw status numbered | sed -nE "s/^\\[[[:space:]]*([0-9]+)\\][[:space:]]+${port}\\/tcp( \\(v6\\))?[[:space:]]+ALLOW IN.*/\\1/p" | head -n1
    )"

    [[ -n "$rule_number" ]] || break
    run_cmd ufw --force delete "$rule_number"
  done
}

configure_firewall() {
  log "Configuring UFW (preserving existing rules)"
  run_cmd ufw --force default deny incoming
  run_cmd ufw --force default allow outgoing
  run_cmd ufw allow "${SSH_PORT}/tcp"

  if ((ALLOW_WEB_PORTS)); then
    run_cmd ufw allow "80/tcp"
    run_cmd ufw allow "443/tcp"
  else
    if [[ "$SSH_PORT" == "80" ]]; then
      log "Skipping removal of 80/tcp because it is configured as SSH port"
    else
      remove_ufw_allow_rule_if_present 80
    fi

    if [[ "$SSH_PORT" == "443" ]]; then
      log "Skipping removal of 443/tcp because it is configured as SSH port"
    else
      remove_ufw_allow_rule_if_present 443
    fi
  fi

  run_cmd ufw --force enable
}

configure_unattended_upgrades() {
  log "Configuring unattended security upgrades"

  if ((DRY_RUN)); then
    log "[dry-run] write $UNATTENDED_AUTO_UPGRADES_FILE"
  else
    cat > "$UNATTENDED_AUTO_UPGRADES_FILE" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
  fi

  run_cmd dpkg-reconfigure -f noninteractive unattended-upgrades
}

configure_fail2ban() {
  log "Configuring fail2ban SSH jail"
  run_cmd mkdir -p "$(dirname "$FAIL2BAN_SSH_JAIL_FILE")"

  if ((DRY_RUN)); then
    log "[dry-run] write $FAIL2BAN_SSH_JAIL_FILE with [sshd] enabled=true port=$SSH_PORT"
    return
  fi

  cat > "$FAIL2BAN_SSH_JAIL_FILE" <<EOF
# Managed by OpenClaw VPS bootstrap script.
[sshd]
enabled = true
port = ${SSH_PORT}
EOF
}

enable_required_services() {
  log "Enabling required services"
  run_cmd systemctl enable --now fail2ban
  run_cmd systemctl restart fail2ban
  run_cmd systemctl enable --now unattended-upgrades
}

prepare_target_user_systemd_services() {
  local user_uid
  local probe_cmd
  local attempt

  SYSTEMD_USER_SERVICES_READY=0
  if ((DRY_RUN)); then
    if user_uid="$(id -u "$TARGET_USER" 2>/dev/null)"; then
      SYSTEMD_USER_RUNTIME_DIR="/run/user/${user_uid}"
      SYSTEMD_USER_BUS_ADDRESS="unix:path=${SYSTEMD_USER_RUNTIME_DIR}/bus"
      log "[dry-run] ensure systemd user services for '$TARGET_USER' (enable linger and start user@${user_uid}.service)"
    else
      SYSTEMD_USER_RUNTIME_DIR="/run/user/<uid>"
      SYSTEMD_USER_BUS_ADDRESS="unix:path=${SYSTEMD_USER_RUNTIME_DIR}/bus"
      log "[dry-run] ensure systemd user services for '$TARGET_USER' (enable linger and start user@<uid>.service after user creation)"
    fi
    SYSTEMD_USER_SERVICES_READY=1
    return 0
  fi

  user_uid="$(id -u "$TARGET_USER")"
  SYSTEMD_USER_RUNTIME_DIR="/run/user/${user_uid}"
  SYSTEMD_USER_BUS_ADDRESS="unix:path=${SYSTEMD_USER_RUNTIME_DIR}/bus"

  probe_cmd="XDG_RUNTIME_DIR='${SYSTEMD_USER_RUNTIME_DIR}' DBUS_SESSION_BUS_ADDRESS='${SYSTEMD_USER_BUS_ADDRESS}' systemctl --user show-environment >/dev/null 2>&1"

  if sudo -u "$TARGET_USER" -H bash -lc "$probe_cmd"; then
    SYSTEMD_USER_SERVICES_READY=1
    return 0
  fi

  if ! command -v loginctl >/dev/null 2>&1; then
    log "loginctl is unavailable. Continuing without systemd user services for '$TARGET_USER'"
    return 1
  fi

  log "Preparing systemd user services for '$TARGET_USER'"
  if ! run_cmd loginctl enable-linger "$TARGET_USER"; then
    log "Could not enable linger for '$TARGET_USER'. Continuing without systemd user services"
    return 1
  fi

  if ! run_cmd systemctl start "user@${user_uid}.service"; then
    log "Could not start user@${user_uid}.service. Continuing without systemd user services"
    return 1
  fi

  for attempt in {1..10}; do
    if sudo -u "$TARGET_USER" -H bash -lc "$probe_cmd"; then
      SYSTEMD_USER_SERVICES_READY=1
      return 0
    fi
    sleep 1
  done

  log "Systemd user services are still unavailable for '$TARGET_USER'. Continuing without user service install support"
  return 1
}

remove_temp_nosudo_file_if_present() {
  if [[ -f "$TEMP_NOSUDO_FILE" ]]; then
    rm -f "$TEMP_NOSUDO_FILE" || true
    log "Removed temporary passwordless sudo for '$TARGET_USER'"
  fi
}

install_temp_nosudo_cleanup_traps() {
  trap 'remove_temp_nosudo_file_if_present' EXIT
  trap 'remove_temp_nosudo_file_if_present; exit 130' INT
  trap 'remove_temp_nosudo_file_if_present; exit 143' TERM
}

clear_temp_nosudo_cleanup_traps() {
  trap - EXIT INT TERM
}

run_openclaw_setup() {
  local cmd_hash
  local existing_hash=""
  local marker_file
  local expected_sudoers_line

  marker_file="$(openclaw_marker_file)"

  cmd_hash="$(printf '%s' "$OPENCLAW_CMD" | sha256sum | awk '{print $1}')"

  if [[ -f "$marker_file" ]]; then
    existing_hash="$(cat "$marker_file" || true)"
  fi

  if [[ "$existing_hash" == "$cmd_hash" ]]; then
    if ((DRY_RUN)); then
      if [[ -f "$TEMP_NOSUDO_FILE" ]]; then
        log "[dry-run] would remove stale temporary passwordless sudo file $TEMP_NOSUDO_FILE"
      fi
    else
      remove_temp_nosudo_file_if_present
    fi
    log "OpenClaw setup command already ran with the same value. Skipping"
    return
  fi

  if ((DRY_RUN)); then
    log "[dry-run] would grant temporary passwordless sudo via $TEMP_NOSUDO_FILE for '$TARGET_USER'"
  else
    install_temp_nosudo_cleanup_traps
    expected_sudoers_line="$(printf '%s ALL=(ALL:ALL) NOPASSWD:ALL' "$TARGET_USER")"
    if [[ -f "$TEMP_NOSUDO_FILE" ]]; then
      if grep -Fxq -- "$expected_sudoers_line" "$TEMP_NOSUDO_FILE"; then
        log "Temporary sudoers file already present for '$TARGET_USER': $TEMP_NOSUDO_FILE"
        run_cmd chown root:root "$TEMP_NOSUDO_FILE"
        run_cmd chmod 440 "$TEMP_NOSUDO_FILE"
      else
        log "Temporary sudoers file exists but does not match '$TARGET_USER'; rewriting"
        printf '%s\n' "$expected_sudoers_line" > "$TEMP_NOSUDO_FILE"
        run_cmd chown root:root "$TEMP_NOSUDO_FILE"
        run_cmd chmod 440 "$TEMP_NOSUDO_FILE"
      fi
    else
      printf '%s\n' "$expected_sudoers_line" > "$TEMP_NOSUDO_FILE"
      run_cmd chown root:root "$TEMP_NOSUDO_FILE"
      run_cmd chmod 440 "$TEMP_NOSUDO_FILE"
      log "Granted temporary passwordless sudo for '$TARGET_USER' during OpenClaw setup"
    fi
  fi

  prepare_target_user_systemd_services || true

  log "Running OpenClaw setup as '$TARGET_USER'"
  if ((SYSTEMD_USER_SERVICES_READY)); then
    log "Using systemd user environment for '$TARGET_USER'"
    if ! run_cmd sudo -u "$TARGET_USER" -H env "XDG_RUNTIME_DIR=${SYSTEMD_USER_RUNTIME_DIR}" "DBUS_SESSION_BUS_ADDRESS=${SYSTEMD_USER_BUS_ADDRESS}" bash -lc "$OPENCLAW_CMD"; then
      die "OpenClaw setup command failed"
    fi
  else
    if ! run_cmd sudo -u "$TARGET_USER" -H bash -lc "$OPENCLAW_CMD"; then
      die "OpenClaw setup command failed"
    fi
  fi

  if ((!DRY_RUN)); then
    remove_temp_nosudo_file_if_present
    clear_temp_nosudo_cleanup_traps
  fi

  if ((DRY_RUN)); then
    log "[dry-run] would record OpenClaw command hash in $marker_file"
  else
    printf '%s\n' "$cmd_hash" > "$marker_file"
  fi
}

switch_to_target_user_shell_if_requested() {
  local switch_mode="stdio"
  local tty_fd=""

  if ((AUTO_SWITCH_TO_USER == 0)); then
    log "Skipping automatic switch to '$TARGET_USER' (--no-switch-user set)"
    return 0
  fi

  if ((DRY_RUN)); then
    log "[dry-run] would switch to login shell for '$TARGET_USER' at the end"
    return 0
  fi

  if [[ ! -t 0 || ! -t 1 ]]; then
    if exec {tty_fd}<> /dev/tty; then
      switch_mode="tty"
      log "Piped/non-interactive stdin detected; using /dev/tty for user switch"
    else
      switch_mode="none"
    fi
  fi

  if [[ "$switch_mode" == "none" ]]; then
    log "Non-interactive shell detected; not switching users. Run manually: sudo -iu $TARGET_USER"
    return 0
  fi

  log "Switching to login shell for '$TARGET_USER' so you can paste pairing approval commands"
  log "Type 'exit' to leave the '$TARGET_USER' shell"
  if [[ "$switch_mode" == "tty" ]]; then
    exec su - "$TARGET_USER" <&"$tty_fd" >&"$tty_fd" 2>&"$tty_fd"
  fi
  exec su - "$TARGET_USER"

  if [[ -n "$tty_fd" ]]; then
    exec {tty_fd}>&-
  fi
  die "Failed to switch to '$TARGET_USER'. Run manually: sudo -iu $TARGET_USER"
}

main() {
  local authorized_key_set=0

  parse_args "$@"
  validate_inputs
  require_root
  validate_os

  [[ -n "$AUTHORIZED_KEY" ]] && authorized_key_set=1

  log "Starting OpenClaw VPS bootstrap"
  log "Configuration: user=$TARGET_USER ssh_port=$SSH_PORT allow_web_ports=$ALLOW_WEB_PORTS dry_run=$DRY_RUN authorized_key_set=$authorized_key_set set_user_password=$SET_USER_PASSWORD auto_switch_user=$AUTO_SWITCH_TO_USER"

  prepare_state_dir
  install_base_packages

  local user_home
  user_home="$(ensure_target_user)"
  set_target_user_password_if_requested

  ensure_target_authorized_keys "$user_home"
  run_openclaw_setup

  backup_ssh_config_once
  write_ssh_hardening_config
  pre_allow_ssh_port_in_firewall
  reload_ssh_service
  configure_firewall
  configure_unattended_upgrades
  configure_fail2ban
  enable_required_services

  log "Bootstrap complete"
  log "Firewall posture: SSH ingress ensured, 80/443 managed by --allow-web-ports, existing UFW rules preserved"
  switch_to_target_user_shell_if_requested
}

main "$@"
