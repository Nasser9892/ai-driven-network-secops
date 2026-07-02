"""
feature_engineering.py
Extracts per-connection and windowed features from Zeek conn.log
for Isolation Forest anomaly detection.
"""

import pandas as pd
import numpy as np
from pathlib import Path

CONN_LOG_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents", "ip_proto"
]

CONN_STATE_MAP = {
    "REJ": 0,
    "RST": 1,
    "S0":  2,
    "SF":  3,
}
FAILED_STATES = {"REJ", "RST", "S0"}

WINDOW_SECONDS = 10


def load_conn_log(filepath: str) -> pd.DataFrame:
    path = Path(filepath)
    rows = []

    with open(path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            rows.append(line.rstrip("\n").split("\t"))

    df = pd.DataFrame(rows, columns=CONN_LOG_COLUMNS)

    df = df.replace("-", np.nan)
    df = df.infer_objects(copy=False)

    numeric_cols = [
        "ts", "id.orig_p", "id.resp_p", "duration",
        "orig_bytes", "resp_bytes", "missed_bytes",
        "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"
    ]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df.sort_values("ts", inplace=True)
    df.reset_index(drop=True, inplace=True)

    return df


def extract_per_connection_features(df: pd.DataFrame) -> pd.DataFrame:
    feat = pd.DataFrame()

    feat["ts"]          = df["ts"]
    feat["src_ip"]      = df["id.orig_h"]
    feat["dst_ip"]      = df["id.resp_h"]
    feat["dst_port"]    = df["id.resp_p"]
    feat["proto"]       = df["proto"]
    feat["conn_state"]  = df["conn_state"]

    orig_bytes = df["orig_bytes"].fillna(0)
    resp_bytes = df["resp_bytes"].fillna(0)
    orig_pkts  = df["orig_pkts"].fillna(0)

    feat["duration"]             = df["duration"].fillna(0)
    feat["orig_bytes"]           = orig_bytes
    feat["resp_bytes"]           = resp_bytes
    feat["orig_pkts"]            = orig_pkts
    feat["packet_to_byte_ratio"] = orig_pkts / (orig_bytes + 1)
    feat["conn_state_encoded"]   = (
        df["conn_state"]
        .map(CONN_STATE_MAP)
        .fillna(4)
        .astype(int)
    )

    return feat


def extract_windowed_features(df: pd.DataFrame) -> pd.DataFrame:
    feat_per_conn = extract_per_connection_features(df)
    results = []

    for src_ip, group in feat_per_conn.groupby("src_ip"):
        group = group.sort_values("ts")
        timestamps = group["ts"].values

        for i, t_start in enumerate(timestamps):
            t_end = t_start + WINDOW_SECONDS

            mask   = (timestamps >= t_start) & (timestamps < t_end)
            window = group[mask]

            if len(window) == 0:
                continue

            total_conns  = len(window)
            failed_count = window["conn_state"].isin(FAILED_STATES).sum()
            orig_bytes   = window["orig_bytes"].sum()
            resp_bytes   = window["resp_bytes"].sum()

            results.append({
                "window_start":      t_start,
                "src_ip":            src_ip,
                "total_conns":       total_conns,
                "unique_dst_ports":  window["dst_port"].nunique(),
                "unique_dst_ips":    window["dst_ip"].nunique(),
                "failed_conn_rate":  failed_count / total_conns,
                "bytes_out_ratio":   orig_bytes / (resp_bytes + 1),
                "conn_per_second":   total_conns / WINDOW_SECONDS,
                "duration":          window["duration"].mean(),
                "orig_bytes":        orig_bytes,
                "resp_bytes":        resp_bytes,
                "orig_pkts":         window["orig_pkts"].sum(),
                "packet_to_byte_ratio": window["packet_to_byte_ratio"].mean(),
                "conn_state_encoded":   window["conn_state_encoded"].mean(),
            })

    return pd.DataFrame(results)


def get_feature_matrix(filepath: str) -> pd.DataFrame:
    print(f"[*] Loading conn.log from {filepath}")
    df = load_conn_log(filepath)
    print(f"[*] Loaded {len(df)} connection records")

    print("[*] Extracting windowed features ...")
    features = extract_windowed_features(df)
    print(f"[*] Feature matrix shape: {features.shape}")

    return features


if __name__ == "__main__":
    LOG_PATH = "/home/ubuntu/secops/logs/conn.log"

    features = get_feature_matrix(LOG_PATH)

    print("\n── Sample output (first 5 rows) ──")
    print(features.head())

    print("\n── Feature stats ──")
    numeric_features = [
        "unique_dst_ports", "unique_dst_ips", "failed_conn_rate",
        "bytes_out_ratio", "conn_per_second", "packet_to_byte_ratio"
    ]
    print(features[numeric_features].describe().round(3))
