#!/usr/bin/env bash
# Containerized end-to-end test: real `yay -S` install through the scan gate.
# Nothing is installed on the host. Requires docker and, for the agent layer,
# YAY_SCAN_BASE_URL / YAY_SCAN_API_KEY / YAY_SCAN_MODEL (OPENAI_* fallbacks).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
model="${YAY_SCAN_MODEL:-${OPENAI_MODEL:-}}"

exec docker run --rm -i \
	-v "$repo_root":/src:ro -w /src \
	-e YAY_SCAN_BASE_URL="${YAY_SCAN_BASE_URL:-${OPENAI_BASE_URL:-}}" \
	-e YAY_SCAN_API_KEY="${YAY_SCAN_API_KEY:-${OPENAI_API_KEY:-}}" \
	-e YAY_SCAN_MODEL="$model" \
	archlinux:latest bash -s <<'CONTAINER'
set -euxo pipefail
# The default fastly mirror intermittently fails; pin one and retry.
echo 'Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch' > /etc/pacman.d/mirrorlist
for attempt in 1 2 3; do
	pacman -Sy --noconfirm --needed base-devel git go sudo && break
	sleep 5
done
pacman -Q go git sudo > /dev/null
echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/builder
useradd -m builder
go build -buildvcs=false -o /usr/local/bin/yay-aur-scan .
runuser -u builder -- mkdir -p /home/builder/yay

# 1. Benign package installs through the gate.
runuser -u builder -- yay-aur-scan -S pipes.sh --noconfirm --builddir /home/builder/yay
runuser -u builder -- yay-aur-scan -Qi pipes.sh
test -f /home/builder/yay/scan/pipes.sh.scan.json

# 2. Second install is served from the scan cache.
runuser -u builder -- yay-aur-scan -S pipes.sh --noconfirm --builddir /home/builder/yay --rebuild 2>&1 |
	tee /tmp/reinstall.log
grep -q "cached result" /tmp/reinstall.log

# 3. Standalone audit works too.
runuser -u builder -- yay-aur-scan -Y --scanonly pipes.sh --builddir /home/builder/yay

echo "E2E OK"
CONTAINER
