#!/usr/bin/env bash
set -euo pipefail

# AdversaryLab - Linux telemetry bootstrap
# Target: Ubuntu 22.04 / 24.04
#
# Installs and validates:
#   - auditd + audispd-plugins
#   - Sysmon for Linux
#
# Azure Monitor Agent and DCR configuration are handled by the Azure deployment.

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
  22.04|24.04) ;;
  *) echo "Warning: Ubuntu ${VERSION_ID} has not been validated by AdversaryLab." >&2 ;;
esac

echo "=== Installing Linux audit stack ==="
apt-get update
apt-get install -y auditd audispd-plugins curl ca-certificates gnupg

systemctl enable auditd
systemctl start auditd

if ! systemctl is-active --quiet auditd; then
  echo "ERROR: auditd is not running." >&2
  systemctl --no-pager --full status auditd || true
  exit 1
fi

echo
echo "=== auditd status ==="
systemctl is-active auditd
auditctl -s

echo
echo "=== Installing Microsoft package repository ==="
repo_deb="/tmp/packages-microsoft-prod.deb"
curl -fsSL "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb" -o "${repo_deb}"
dpkg -i "${repo_deb}"
rm -f "${repo_deb}"

apt-get update

echo
echo "=== Installing Sysmon for Linux ==="
apt-get install -y sysinternalsebpf sysmonforlinux

CONFIG_PATH="/etc/sysmonconfig-adversarylab.xml"

echo
echo "=== Writing AdversaryLab Sysmon configuration ==="
cat > "${CONFIG_PATH}" <<'EOF'
<Sysmon schemaversion="4.81">
  <EventFiltering>

    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude"/>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="exclude"/>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="exclude"/>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="exclude"/>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude"/>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <FileDelete onmatch="exclude"/>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
EOF

echo
echo "=== Applying Sysmon configuration ==="
if sysmon -c >/dev/null 2>&1; then
  sysmon -c "${CONFIG_PATH}"
else
  sysmon -accepteula -i "${CONFIG_PATH}"
fi

systemctl enable sysmon
systemctl start sysmon

if ! systemctl is-active --quiet sysmon; then
  echo "ERROR: Sysmon is not running." >&2
  systemctl --no-pager --full status sysmon || true
  exit 1
fi

echo
echo "=== Sysmon status ==="
systemctl is-active sysmon

echo
echo "=== Active Sysmon configuration ==="
sysmon -c

echo
echo "=== Recent Sysmon service messages ==="
journalctl -u sysmon --no-pager -n 20 || true

if [[ -f /var/log/syslog ]]; then
  echo
  echo "=== Recent Sysmon syslog messages ==="
  grep -i sysmon /var/log/syslog | tail -n 20 || true
fi

echo
echo "Linux telemetry bootstrap complete."
echo "auditd: PASS"
echo "Sysmon: PASS"
echo "Next: run scripts/Test-LinuxTelemetry.sh and then confirm AMA/DCR ingestion in Log Analytics."
