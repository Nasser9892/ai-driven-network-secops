#!/usr/bin/env python3
import json, time, os, urllib.request

ALERTS_FILE = "/home/ubuntu/secops/logs/alerts.json"
DASHBOARD_URL = "http://10.0.1.36:8000/ingest-alert"
STATE_FILE = "/home/ubuntu/secops/.sync_state"

def get_last_line():
    try:
        with open(STATE_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return 0

def set_last_line(n):
    with open(STATE_FILE, "w") as f:
        f.write(str(n))

def post_alert(a):
    evidence = f"total_conns={a.get('total_conns','?')}, unique_dst_ports={a.get('unique_dst_ports','?')}, failed_conn_rate={a.get('failed_conn_rate','?')}"
    payload = {
        "timestamp": a.get("timestamp", ""),
        "src_ip": a.get("src_ip", ""),
        "anomaly_score": float(a.get("anomaly_score", 0.0)),
        "mitre_technique": a.get("mitre", ""),
        "risk_level": a.get("severity", ""),
        "evidence": evidence
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(DASHBOARD_URL, data=data,
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)

def main():
    while True:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE) as f:
                lines = f.readlines()
            last = get_last_line()
            for i in range(last, len(lines)):
                line = lines[i].strip()
                if not line:
                    continue
                try:
                    post_alert(json.loads(line))
                    print(f"Synced line {i}")
                except Exception as e:
                    print(f"Error line {i}: {e}")
            set_last_line(len(lines))
        time.sleep(10)

if __name__ == "__main__":
    main()
