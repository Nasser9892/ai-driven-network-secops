# Security Hardening

Operational safeguards for the AI-driven SecOps platform.

## disk-guard.sh — Automatic Disk Cleanup

### Problem
`secops-detection` runs a 12 GB root volume shared by Wazuh + the ML engine.
Wazuh's Vulnerability Detection module downloads a compressed CVE database
(~350 MB `.tar.xz`) and extracts it into `/var/ossec/tmp`, producing a ~7 GB
`.tar`. If extraction is interrupted (e.g. the disk fills mid-process), the
temporary file is left behind and never cleaned up, filling the disk to 100%
and breaking Wazuh, the ML pipeline, and log ingestion.

### Solution
`disk-guard.sh` is a threshold-based cleaner (not a fixed schedule). It runs
every 10 minutes via `/etc/cron.d/disk-guard` and only acts when root disk
usage exceeds **85%**. Cleanup is oldest-first and escalates in stages:

1. Delete Wazuh `/var/ossec/tmp` leftovers (safe — regenerated on demand).
2. Vacuum the systemd journal down to 100 MB.
3. Delete rotated/compressed logs in `/var/log` older than 3 days.
4. If still over threshold: delete Wazuh archive/alert logs older than 3 days.

Each run logs the result to syslog via `logger -t disk-guard`.

### Files
| Path (on secops-detection) | Purpose |
|---|---|
| `/usr/local/bin/disk-guard.sh` | Cleanup script |
| `/etc/cron.d/disk-guard` | Cron entry — runs every 10 min as root |

### Verification
```bash
sudo /usr/local/bin/disk-guard.sh   # manual run
df -h /                             # confirm usage dropped
grep disk-guard /var/log/syslog     # see cleanup log lines
```

### Backlog / production notes
- The 85% threshold and 3-day retention are conservative defaults for a demo
  environment; production should tune per-volume.
- A longer-term fix is to disable Wazuh Vulnerability Detection (not needed
  for network-anomaly/MITRE detection) or grow the EBS volume.
