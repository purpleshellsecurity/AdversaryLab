#!/usr/bin/env bash
set -euo pipefail

# AdversaryLab - Sysmon for Linux bootstrap
# Target: Ubuntu 24.04 LTS
# Installs Microsoft's package repository and Sysmon for Linux, then validates
# that the service and local syslog path are available before AMA ingestion is
# tested.

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

. /etc/os-release
if [[ "${ID}" != "ubuntu" ]]; then
  echo "This installer currently supports Ubuntu only (found: ${ID})." >&2
  exit 1
fi

case "${VERSION_ID}" in
  24.04|22.04) ;;
  *) echo "Warning: Ubuntu ${VERSION_ID} has not been validated by AdversaryLab." >&2 ;;
esac

apt-get update
apt-get install -y curl ca-certificates gnupg

repo_deb="/tmp/packages-microsoft-prod.deb"
curl -fsSL "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb" -o "${repo_deb}"
dpkg -i "${repo_deb}"
rm -f "${repo_deb}"

apt-get update
# sysinternalsebpf is an explicit dependency in Microsoft's documented package
# install path for Sysmon for Linux.
apt-get install -y sysinternalsebpf sysmonforlinux

CONFIG_PATH="${1:-}"
if [[ -n "${CONFIG_PATH}" ]]; then
  if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "Sysmon config not found: ${CONFIG_PATH}" >&2
    exit 1
  fi
  sysmon -accepteula -i "${CONFIG_PATH}" || sysmon -c "${CONFIG_PATH}"
else
  # Package installation may already register/start Sysmon. If not, initialise
  # it with the built-in configuration so telemetry can be validated first.
  sysmon -accepteula -i || true
fi

systemctl enable --now sysmon || true

echo
echo "=== Sysmon service ==="
systemctl --no-pager --full status sysmon || true

echo
echo "=== Recent Sysmon messages ==="
if command -v journalctl >/dev/null 2>&1; then
  journalctl -u sysmon --no-pager -n 20 || true
fi
if [[ -f /var/log/syslog ]]; then
  grep -i sysmon /var/log/syslog | tail -n 20 || true
fi

echo
echo "Sysmon for Linux bootstrap complete."
echo "Next validation: generate process/network activity and confirm records in the Log Analytics Syslog table."
