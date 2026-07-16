#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo ./install-boot-services.sh" >&2
  exit 1
fi

apt-get update
apt-get install -y tcpdump iproute2 python3-flask

install -m 0644 systemd/lanman-capture.service /etc/systemd/system/lanman-capture.service
install -m 0644 systemd/lanman-dashboard.service /etc/systemd/system/lanman-dashboard.service

systemctl daemon-reload
systemctl enable lanman-capture.service lanman-dashboard.service
systemctl restart lanman-capture.service
systemctl restart lanman-dashboard.service

systemctl --no-pager --full status lanman-capture.service lanman-dashboard.service
