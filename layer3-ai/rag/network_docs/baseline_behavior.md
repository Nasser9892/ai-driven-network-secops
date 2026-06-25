# Baseline Network Behavior

## Normal Traffic Patterns
- conn_per_second < 10 per source IP
- unique_dst_ports < 5 per 10 second window
- failed_conn_rate < 0.1
- bytes_out_ratio < 2.0
- packet_to_byte_ratio < 10

## Alert Thresholds
- Port Scan: unique_dst_ports > 15 in 10 seconds
- Brute Force: failed_conn_rate > 0.5
- Data Exfiltration: bytes_out_ratio > 10
- C2 Beaconing: connection regularity > 0.9
- DNS Tunneling: query_entropy > 3.5

## Known Good Traffic
- Zeek rsync to secops-detection every 30 seconds
- Wazuh agent heartbeat every 60 seconds
- SSH sessions from management IPs only
