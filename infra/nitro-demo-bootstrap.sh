#!/usr/bin/env bash
# EC2 user data: fresh Amazon Linux 2023 x86_64, enclave-enabled m6i.xlarge.
# Install host tools only. Does not create a wallet, enable bridge actions or run a prover.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as EC2 root user data.' >&2; exit 1; }

# Preserve an absolute deadline if cloud-init is rerun; a reboot must not extend it.
# Set EC2 InstanceInitiatedShutdownBehavior=stop before launch.
if [[ ! -s /etc/cwxmr-demo-stop-at ]]; then
  date -u -d '+15 hours' '+%Y-%m-%d %H:%M:%S UTC' > /etc/cwxmr-demo-stop-at
fi
read -r CWXMR_STOP_AT < /etc/cwxmr-demo-stop-at
cat > /etc/systemd/system/cwxmr-budget-stop.service <<'UNIT'
[Unit]
Description=Stop the cwXMR demo parent at its budget deadline
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl poweroff
UNIT
cat > /etc/systemd/system/cwxmr-budget-stop.timer <<UNIT
[Unit]
Description=Fixed cwXMR demo stop deadline
[Timer]
OnCalendar=${CWXMR_STOP_AT}
Persistent=true
AccuracySec=1s
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now cwxmr-budget-stop.timer

# Install only after the stop timer is active, so a failed package install leaves the guard.
dnf install -y docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel git jq python3
usermod -aG ne,docker ec2-user
cat > /etc/nitro_enclaves/allocator.yaml <<'YAML'
---
memory_mib: 8192
cpu_count: 2
YAML
systemctl enable --now docker
systemctl enable nitro-enclaves-allocator.service
systemctl restart nitro-enclaves-allocator.service
nitro-cli --version
systemctl list-timers --all cwxmr-budget-stop.timer
