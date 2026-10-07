#!/usr/bin/env bash
set -euo pipefail

# AdversaryLab - Linux local telemetry validation
#
# Proves that:
#   - auditd is installed and active
#   - an audit watch records test activity
#   - Sysmon for Linux is active and configured
#   - basic process/file/network activity is generated for Sysmon
#
# This script validates local telemetry only. AMA/DCR -> Log Analytics
# ingestion should be checked separately after running it.

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

TEST_DIR="/tmp/adversarylab-linux-telemetry"
TEST_FILE="${TEST_DIR}/audit-test.txt"
TEST_KEY="adversarylab_test"
RULE_ADDED=0

cleanup() {
  if [[ "${RULE_ADDED}" -eq 1 ]]; then
    auditctl -W "${TEST_DIR}" -p rwa -k "${TEST_KEY}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TEST_DIR}"
}
trap cleanup EXIT

echo "=== auditd ==="
if ! command -v auditctl >/dev/null 2>&1; then
  echo "FAIL: auditctl is not installed." >&2
  exit 1
fi

if ! systemctl is-active --quiet auditd; then
  echo "FAIL: auditd is not active." >&2
  exit 1
fi

echo "PASS: auditd is active"
auditctl -s

mkdir -p "${TEST_DIR}"

echo
echo "=== auditd test rule ==="
auditctl -w "${TEST_DIR}" -p rwa -k "${TEST_KEY}"
RULE_ADDED=1

touch "${TEST_FILE}"
printf 'adversarylab audit test\n' > "${TEST_FILE}"
cat "${TEST_FILE}" >/dev/null

sleep 1

if ausearch -k "${TEST_KEY}" -ts recent | grep -q "${TEST_KEY}"; then
  echo "PASS: audit event observed for key ${TEST_KEY}"
else
  echo "FAIL: no audit event observed for key ${TEST_KEY}" >&2
  ausearch -k "${TEST_KEY}" -ts recent || true
  exit 1
fi

echo
echo "=== Sysmon for Linux ==="
if ! command -v sysmon >/dev/null 2>&1; then
  echo "FAIL: sysmon is not installed." >&2
  exit 1
fi

if ! systemctl is-active --quiet sysmon; then
  echo "FAIL: Sysmon service is not active." >&2
  systemctl --no-pager --full status sysmon || true
  exit 1
fi

echo "PASS: Sysmon service is active"
sysmon -c

echo
echo "=== generating Sysmon-observable activity ==="
/bin/bash -c 'echo adversarylab-sysmon-test > /tmp/adversarylab-sysmon-test.txt'
/bin/cat /tmp/adversarylab-sysmon-test.txt >/dev/null
/bin/rm -f /tmp/adversarylab-sysmon-test.txt

if command -v curl >/dev/null 2>&1; then
  curl -fsSI --max-time 10 https://example.com >/dev/null 2>&1 || true
fi

sleep 2

echo
echo "=== recent Sysmon service messages ==="
journalctl -u sysmon --no-pager -n 50 || true

if [[ -f /var/log/syslog ]]; then
  echo
  echo "=== recent Sysmon syslog messages ==="
  grep -i sysmon /var/log/syslog | tail -n 50 || true
fi

echo
echo "Local Linux telemetry validation complete."
echo "auditd: PASS"
echo "Sysmon: PASS"
echo "Next: validate Syslog/Sysmon rows in Log Analytics through AMA/DCR."
