"""Dataset preparation, cleaning, labeling, and synthetic fixture generation."""

import os
from pathlib import Path
from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from threatsense.features.schema import FEATURE_NAMES
from threatsense.logging import logger

ATTACK_CLASSES = ["BENIGN", "DoS/DDoS", "PortScan", "BruteForce", "Botnet"]

# Mapping from raw CIC-IDS2017 labels to canonical classes
CIC_LABEL_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS/DDoS",
    "DoS GoldenEye": "DoS/DDoS",
    "DoS slowloris": "DoS/DDoS",
    "DoS Slowhttptest": "DoS/DDoS",
    "DDoS": "DoS/DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Bot": "Botnet",
}


def generate_synthetic_dataset(n_samples: int = 10000, random_seed: int = 42) -> pd.DataFrame:
    """Generates realistic synthetic flow data modeling CIC-IDS2017 distributions."""
    rng = np.random.default_rng(random_seed)
    records = []

    # Distribution of classes: 65% Benign, 15% DoS, 10% PortScan, 5% BruteForce, 5% Botnet
    classes = rng.choice(ATTACK_CLASSES, size=n_samples, p=[0.65, 0.15, 0.10, 0.05, 0.05])

    for label in classes:
        if label == "BENIGN":
            duration = rng.exponential(scale=2.5)
            orig_bytes = int(rng.gamma(shape=2.0, scale=800.0))
            resp_bytes = int(rng.gamma(shape=3.0, scale=4000.0))
            orig_pkts = max(1, int(orig_bytes / rng.uniform(200, 1400)) + rng.integers(1, 10))
            resp_pkts = max(1, int(resp_bytes / rng.uniform(400, 1400)) + rng.integers(1, 15))
            port = int(rng.choice([80, 443, 53, 8080, 22, 123, 8443]))

        elif label == "DoS/DDoS":
            # High packet rate, asymmetric orig vs resp, small packet size or zero resp
            duration = rng.uniform(0.001, 1.5)
            orig_pkts = rng.integers(500, 15000)
            orig_bytes = orig_pkts * rng.integers(40, 120)
            resp_pkts = rng.integers(0, 10)
            resp_bytes = resp_pkts * rng.integers(40, 80)
            port = int(rng.choice([80, 443, 8080, 53]))

        elif label == "PortScan":
            # Very short, 1 packet, zero or minimal bytes, varied ports
            duration = rng.uniform(0.0, 0.01)
            orig_pkts = rng.choice([1, 2])
            orig_bytes = orig_pkts * 40
            resp_pkts = rng.choice([0, 1])
            resp_bytes = resp_pkts * 40
            port = int(rng.integers(1, 65535))

        elif label == "BruteForce":
            # Repeated short sessions on auth ports (22, 21), fixed small payload sizes
            duration = rng.uniform(0.5, 2.5)
            orig_pkts = rng.integers(8, 25)
            orig_bytes = orig_pkts * rng.integers(45, 80)
            resp_pkts = rng.integers(8, 25)
            resp_bytes = resp_pkts * rng.integers(60, 120)
            port = int(rng.choice([22, 21, 3389]))

        else:  # Botnet
            # Periodic long duration or beaconing to non-standard high ports
            duration = rng.uniform(10.0, 300.0)
            orig_pkts = rng.integers(15, 80)
            orig_bytes = orig_pkts * rng.integers(50, 150)
            resp_pkts = rng.integers(15, 80)
            resp_bytes = resp_pkts * rng.integers(50, 200)
            port = int(rng.choice([6667, 8000, 9999, 4444, 8088]))

        total_bytes = orig_bytes + resp_bytes
        total_pkts = orig_pkts + resp_pkts
        dur_eps = duration + 1e-6
        bytes_per_sec = total_bytes / dur_eps
        pkts_per_sec = total_pkts / dur_eps
        orig_to_resp_byte_ratio = float(orig_bytes) / (float(resp_bytes) + 1.0)
        orig_to_resp_pkt_ratio = float(orig_pkts) / (float(resp_pkts) + 1.0)

        record = {
            "duration": float(duration),
            "orig_bytes": int(orig_bytes),
            "resp_bytes": int(resp_bytes),
            "orig_pkts": int(orig_pkts),
            "resp_pkts": int(resp_pkts),
            "total_bytes": int(total_bytes),
            "total_pkts": int(total_pkts),
            "bytes_per_sec": float(bytes_per_sec),
            "pkts_per_sec": float(pkts_per_sec),
            "orig_to_resp_byte_ratio": float(orig_to_resp_byte_ratio),
            "orig_to_resp_pkt_ratio": float(orig_to_resp_pkt_ratio),
            "dst_port": int(port),
            "label": label,
        }
        records.append(record)

    df = pd.DataFrame(records)
    return df


def load_and_preprocess_data(
    raw_data_path: str = "./data/raw",
    processed_data_dir: str = "./data/processed",
    test_size: float = 0.20,
    random_seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Loads CIC-IDS2017 CSV files if available, otherwise generates validated synthetic dataset."""
    raw_path = Path(raw_data_path)
    csv_files = list(raw_path.glob("*.csv")) if raw_path.exists() else []

    if csv_files:
        logger.info(f"Found {len(csv_files)} real dataset CSV files in {raw_data_path}")
        dfs = []
        for f in csv_files:
            try:
                temp_df = pd.read_csv(f, nrows=50000)
                temp_df.columns = temp_df.columns.str.strip()
                dfs.append(temp_df)
            except Exception as e:
                logger.warning(f"Error reading {f}: {e}")
        if dfs:
            combined = pd.concat(dfs, ignore_index=True)
            # Map columns to canonical schema
            # Flow Duration (in microsec) -> duration in sec
            df = pd.DataFrame()
            if "Flow Duration" in combined.columns:
                df["duration"] = combined["Flow Duration"] / 1e6
                df["orig_bytes"] = combined.get("Total Length of Fwd Packets", 0)
                df["resp_bytes"] = combined.get("Total Length of Bwd Packets", 0)
                df["orig_pkts"] = combined.get("Total Fwd Packets", 0)
                df["resp_pkts"] = combined.get("Total Backward Packets", 0)
                df["total_bytes"] = df["orig_bytes"] + df["resp_bytes"]
                df["total_pkts"] = df["orig_pkts"] + df["resp_pkts"]
                df["bytes_per_sec"] = df["total_bytes"] / (df["duration"] + 1e-6)
                df["pkts_per_sec"] = df["total_pkts"] / (df["duration"] + 1e-6)
                df["orig_to_resp_byte_ratio"] = df["orig_bytes"] / (df["resp_bytes"] + 1.0)
                df["orig_to_resp_pkt_ratio"] = df["orig_pkts"] / (df["resp_pkts"] + 1.0)
                df["dst_port"] = combined.get("Destination Port", 80)
                # Map label
                raw_label = combined.get("Label", "BENIGN")
                df["label"] = raw_label.map(lambda x: CIC_LABEL_MAP.get(str(x).strip(), "BENIGN"))
    else:
        logger.info("No raw CSV files found in data/raw. Generating validated synthetic dataset.")
        df = generate_synthetic_dataset(n_samples=15000, random_seed=random_seed)

    # Clean duplicates and infinite/NaN values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)

    # Train/Test Stratified Split
    train_df, test_df = train_test_split(
        df, test_size=test_size, stratify=df["label"], random_state=random_seed
    )

    out_dir = Path(processed_data_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_df.to_csv(out_dir / "train_features.csv", index=False)
    test_df.to_csv(out_dir / "test_features.csv", index=False)
    logger.info(f"Saved {len(train_df)} train samples and {len(test_df)} test samples to {out_dir}")

    return train_df, test_df
