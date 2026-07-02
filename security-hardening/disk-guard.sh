#!/bin/bash
# Auto disk cleanup when usage exceeds threshold. Oldest-first.
THRESHOLD=85
usage() { df / | awk 'NR==2 {gsub("%",""); print $5}'; }

[ "$(usage)" -lt "$THRESHOLD" ] && exit 0

# 1. Wazuh tmp leftovers (safe, regenerated on demand)
find /var/ossec/tmp -type f -mtime +0 -delete 2>/dev/null

# 2. Vacuum systemd journal down to 100M
journalctl --vacuum-size=100M 2>/dev/null

# 3. Rotated/compressed logs older than 3 days
find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) -mtime +3 -delete 2>/dev/null

# 4. Wazuh archive logs older than 3 days (if still over threshold)
if [ "$(usage)" -ge "$THRESHOLD" ]; then
  find /var/ossec/logs/archives -type f -mtime +3 -delete 2>/dev/null
  find /var/ossec/logs/alerts  -type f -name "*.log" -mtime +3 -delete 2>/dev/null
fi

logger -t disk-guard "Cleanup ran. Usage now: $(usage)%"
