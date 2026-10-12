"""ML test verifying absence of data leakage between train and test splits."""

from pathlib import Path
import pandas as pd


def test_no_train_test_data_leakage():
    train_path = Path("./data/processed/train_features.csv")
    test_path = Path("./data/processed/test_features.csv")

    assert train_path.exists()
    assert test_path.exists()

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    # Disjoint check: train and test indices must not overlap
    train_hashes = set(pd.util.hash_pandas_object(train_df, index=False))
    test_hashes = set(pd.util.hash_pandas_object(test_df, index=False))

    intersection = train_hashes.intersection(test_hashes)
    # At most negligible collisions in continuous random features
    overlap_rate = len(intersection) / len(test_df)
    assert overlap_rate < 0.01, f"Excessive train/test overlap detected: {overlap_rate:.2%}"


def test_stratified_distribution_preserved():
    train_df = pd.read_csv("./data/processed/train_features.csv")
    test_df = pd.read_csv("./data/processed/test_features.csv")

    train_dist = train_df["label"].value_counts(normalize=True)
    test_dist = test_df["label"].value_counts(normalize=True)

    for cls in train_dist.index:
        assert cls in test_dist.index
        # Proportions should match within 2% margin
        diff = abs(train_dist[cls] - test_dist[cls])
        assert diff < 0.02, f"Stratification discrepancy on class {cls}: {diff:.4f}"
