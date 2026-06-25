"""
train_model.py
Trains an Isolation Forest model on baseline (normal) traffic
extracted from Zeek conn.log and saves it to disk.
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_engineering import get_feature_matrix

# ── Paths ─────────────────────────────────────────────────────────────────────
LOG_PATH   = "/home/ubuntu/secops/logs/conn.log"
MODEL_DIR  = Path("/home/ubuntu/secops/ml-engine/models")
MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"

# ── Feature columns fed into the model ────────────────────────────────────────
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


def train(contamination: float = 0.01, n_estimators: int = 100) -> None:
    """
    Load conn.log, extract features, train Isolation Forest, save model.

    contamination: expected fraction of anomalies in training data (1%)
    n_estimators:  number of trees in the forest
    """
    # -- Load and extract features --
    features = get_feature_matrix(LOG_PATH)

    if features.empty:
        print("[!] No features extracted — check conn.log")
        return

    # -- Select and clean feature matrix --
    X = features[FEATURE_COLS].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    print(f"[*] Training on {len(X)} samples, {len(FEATURE_COLS)} features")

    # -- Scale features (important for distance-based calculations) --
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # -- Train Isolation Forest --
    model = IsolationForest(
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=42,
        n_jobs=-1,       # use all CPU cores
    )
    model.fit(X_scaled)

    # -- Save model and scaler --
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print(f"[*] Model saved to  {MODEL_PATH}")
    print(f"[*] Scaler saved to {SCALER_PATH}")

    # -- Quick sanity check: score the training data --
    scores = model.decision_function(X_scaled)
    anomaly_count = (model.predict(X_scaled) == -1).sum()

    print(f"\n── Sanity check ──")
    print(f"    Anomaly score range : {scores.min():.3f} to {scores.max():.3f}")
    print(f"    Flagged as anomaly  : {anomaly_count} / {len(X)} ({anomaly_count/len(X)*100:.1f}%)")
    print(f"    (expected ~{contamination*100:.0f}% with contamination={contamination})")


if __name__ == "__main__":
    train()
