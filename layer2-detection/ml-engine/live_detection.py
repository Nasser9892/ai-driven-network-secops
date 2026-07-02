"""
live_detection.py
Tails Zeek conn.log in real-time, scores each new connection
using the trained Isolation Forest model, and prints alerts
for anomalies. This is the live detection pipeline.
"""

import time
import json
import ipaddress
import urllib.request
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

from feature_engineering import (
    CONN_LOG_COLUMNS,
    CONN_STATE_MAP,
    FAILED_STATES,
    WINDOW_SECONDS,
    load_conn_log,
    extract_windowed_features,
)

LOG_PATH    = "/home/ubuntu/secops/logs/conn.log"
MODEL_PATH  = "/home/ubuntu/secops/ml-engine/models/isolation_forest.pkl"
SCALER_PATH = "/home/ubuntu/secops/ml-engine/models/scaler.pkl"
ALERT_LOG   = "/home/ubuntu/secops/logs/alerts.json"

ANOMALY_THRESHOLD = -0.05
POLL_INTERVAL     = 5
ALERT_COOLDOWN    = 300

INTERNAL_CIDR = ipaddress.ip_network("10.0.0.0/16")

def is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in INTERNAL_CIDR
    except ValueError:
        return False

N8N_WEBHOOK = "http://10.0.1.90:5678/webhook/secops-alert"
N8N_TIMEOUT = 300

FEATURE_COLS = [
    "unique_dst_ports",
    "unique_dst_ips",
    "failed_conn_rate",
    "bytes_out_ratio",
    "conn_per_second",
    "packet_to_byte_ratio",
    "conn_state_encoded",
    "duration",
    "orig_bytes",
    "orig_pkts",
]


def send_to_n8n(alert: dict) -> None:
    try:
        payload = json.dumps(alert).encode("utf-8")
        req = urllib.request.Request(
            N8N_WEBHOOK,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=N8N_TIMEOUT) as resp:
            print(f"[n8n] Alert sent — status: {resp.status}")
    except Exception as e:
        print(f"[n8n] Failed to send alert: {e}")


def load_model():
    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print(f"[*] Model loaded from {MODEL_PATH}")
    return model, scaler


def score_features(features: pd.DataFrame, model, scaler) -> pd.DataFrame:
    X = features[FEATURE_COLS].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    X_scaled = scaler.transform(X)
    scores   = model.decision_function(X_scaled)
    labels   = model.predict(X_scaled)

    features = features.copy()
    features["anomaly_score"] = scores
    features["is_anomaly"]    = labels == -1

    return features


def format_alert(row: pd.Series) -> dict:
    return {
        "timestamp":        datetime.utcnow().isoformat() + "Z",
        "src_ip":           row["src_ip"],
        "anomaly_score":    round(float(row["anomaly_score"]), 4),
        "unique_dst_ports": int(row["unique_dst_ports"]),
        "unique_dst_ips":   int(row["unique_dst_ips"]),
        "failed_conn_rate": round(float(row["failed_conn_rate"]), 3),
        "conn_per_second":  round(float(row["conn_per_second"]), 3),
        "bytes_out_ratio":  round(float(row["bytes_out_ratio"]), 3),
        "total_conns":      int(row["total_conns"]),
        "severity":         "CRITICAL" if row["anomaly_score"] < -0.15 else "HIGH",
        "alert_type":       "network_anomaly",
        "mitre":            "T1046",
    }


def write_alert(alert: dict) -> None:
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")


def run() -> None:
    model, scaler = load_model()

    print(f"[*] Starting live detection — polling every {POLL_INTERVAL}s")
    print(f"[*] Anomaly threshold: {ANOMALY_THRESHOLD}")
    print(f"[*] Alert cooldown: {ALERT_COOLDOWN}s per src_ip")
    print(f"[*] Internal CIDR excluded: {INTERNAL_CIDR}")
    print(f"[*] Alert log: {ALERT_LOG}")
    print("-" * 60)

    last_alert_time = {}

    while True:
        try:
            df = load_conn_log(LOG_PATH)

            if df.empty:
                time.sleep(POLL_INTERVAL)
                continue

            features = extract_windowed_features(df)

            if features.empty:
                time.sleep(POLL_INTERVAL)
                continue

            scored = score_features(features, model, scaler)
            anomalies = scored[scored["is_anomaly"]]

            now = time.time()

            for _, row in anomalies.iterrows():
                src_ip = row["src_ip"]

                if is_internal(src_ip):
                    continue

                last_seen = last_alert_time.get(src_ip, 0)
                if now - last_seen < ALERT_COOLDOWN:
                    continue

                last_alert_time[src_ip] = now

                alert = format_alert(row)
                write_alert(alert)

                print(
                    f"[{alert['severity']}] {alert['timestamp']} | "
                    f"src={alert['src_ip']} | "
                    f"score={alert['anomaly_score']} | "
                    f"ports={alert['unique_dst_ports']} | "
                    f"conns/s={alert['conn_per_second']} | "
                    f"fail_rate={alert['failed_conn_rate']}"
                )

                send_to_n8n(alert)

        except Exception as e:
            print(f"[!] Error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
