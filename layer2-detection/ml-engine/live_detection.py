"""
live_detection.py
Tails Zeek conn.log in real-time, scores each new connection
using the trained Isolation Forest model, and prints alerts
for anomalies. This is the live detection pipeline.
"""

import time
import json
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

# ── Paths ─────────────────────────────────────────────────────────────────────
LOG_PATH    = "/home/ubuntu/secops/logs/conn.log"
MODEL_PATH  = "/home/ubuntu/secops/ml-engine/models/isolation_forest.pkl"
SCALER_PATH = "/home/ubuntu/secops/ml-engine/models/scaler.pkl"
ALERT_LOG   = "/home/ubuntu/secops/logs/alerts.json"

# ── Thresholds ────────────────────────────────────────────────────────────────
ANOMALY_THRESHOLD = -0.05   # scores below this trigger an alert
POLL_INTERVAL     = 5       # seconds between conn.log reads

# ── Feature columns (must match train_model.py) ───────────────────────────────
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


def load_model():
    """Load the trained Isolation Forest and scaler from disk."""
    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print(f"[*] Model loaded from {MODEL_PATH}")
    return model, scaler


def score_features(features: pd.DataFrame, model, scaler) -> pd.DataFrame:
    """
    Scale features and run Isolation Forest scoring.
    Adds 'anomaly_score' and 'is_anomaly' columns to the DataFrame.
    """
    X = features[FEATURE_COLS].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    X_scaled = scaler.transform(X)
    scores   = model.decision_function(X_scaled)   # higher = more normal
    labels   = model.predict(X_scaled)             # 1 = normal, -1 = anomaly

    features = features.copy()
    features["anomaly_score"] = scores
    features["is_anomaly"]    = labels == -1

    return features


def format_alert(row: pd.Series) -> dict:
    """Build a structured alert payload from an anomalous feature row."""
    return {
        "timestamp":          datetime.utcnow().isoformat() + "Z",
        "src_ip":             row["src_ip"],
        "anomaly_score":      round(float(row["anomaly_score"]), 4),
        "unique_dst_ports":   int(row["unique_dst_ports"]),
        "unique_dst_ips":     int(row["unique_dst_ips"]),
        "failed_conn_rate":   round(float(row["failed_conn_rate"]), 3),
        "conn_per_second":    round(float(row["conn_per_second"]), 3),
        "bytes_out_ratio":    round(float(row["bytes_out_ratio"]), 3),
        "total_conns":        int(row["total_conns"]),
        "severity":           "CRITICAL" if row["anomaly_score"] < -0.15 else "HIGH",
    }


def write_alert(alert: dict) -> None:
    """Append alert as a JSON line to the alert log file."""
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")


def run() -> None:
    """
    Main loop: every POLL_INTERVAL seconds, reload conn.log,
    extract features, score them, and print/log any anomalies.
    """
    model, scaler = load_model()

    print(f"[*] Starting live detection — polling every {POLL_INTERVAL}s")
    print(f"[*] Anomaly threshold: {ANOMALY_THRESHOLD}")
    print(f"[*] Alert log: {ALERT_LOG}")
    print("-" * 60)

    seen_windows = set()   # avoid re-alerting the same window

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

            for _, row in anomalies.iterrows():
                # Deduplicate: same src_ip + window_start
                key = (row["src_ip"], round(row["window_start"], 0))
                if key in seen_windows:
                    continue
                seen_windows.add(key)

                alert = format_alert(row)
                write_alert(alert)

                # Print to terminal
                print(
                    f"[{alert['severity']}] {alert['timestamp']} | "
                    f"src={alert['src_ip']} | "
                    f"score={alert['anomaly_score']} | "
                    f"ports={alert['unique_dst_ports']} | "
                    f"conns/s={alert['conn_per_second']} | "
                    f"fail_rate={alert['failed_conn_rate']}"
                )

        except Exception as e:
            print(f"[!] Error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
