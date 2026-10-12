"""Unit tests for feature extraction and schema compatibility layer."""

from threatsense.features.schema import FEATURE_NAMES, CANONICAL_FEATURES
from threatsense.features.extractor import FlowFeatureExtractor
from threatsense.features.compatibility import FeatureCompatibilityValidator


def test_canonical_features_count():
    assert len(CANONICAL_FEATURES) == 12
    assert len(FEATURE_NAMES) == 12


def test_flow_feature_extractor_derived_rates():
    raw_dict = {
        "duration": 2.0,
        "orig_bytes": 1000,
        "resp_bytes": 3000,
        "orig_pkts": 10,
        "resp_pkts": 30,
        "dst_port": 443,
    }
    feats = FlowFeatureExtractor.extract_features(raw_dict)
    assert feats["total_bytes"] == 4000
    assert feats["total_pkts"] == 40
    assert round(feats["bytes_per_sec"], 1) == 2000.0
    assert round(feats["pkts_per_sec"], 1) == 20.0
    assert feats["dst_port"] == 443


def test_compatibility_validator_success():
    raw_dict = {
        "duration": 1.5,
        "orig_bytes": 500,
        "resp_bytes": 1500,
        "orig_pkts": 5,
        "resp_pkts": 15,
        "dst_port": 80,
    }
    feats = FlowFeatureExtractor.extract_features(raw_dict)
    res = FeatureCompatibilityValidator.validate(feats)
    assert res.is_compatible is True
    assert res.status_code == "COMPATIBLE"


def test_compatibility_validator_missing_feature_rejected():
    feats = {"duration": 1.0, "orig_bytes": 100}  # Incomplete feature dictionary
    res = FeatureCompatibilityValidator.validate(feats)
    assert res.is_compatible is False
    assert res.status_code == "FEATURE_SCHEMA_INCOMPATIBLE"
    assert len(res.missing_features) > 0


def test_compatibility_validator_invalid_values_rejected():
    raw_dict = {
        "duration": 1.0,
        "orig_bytes": 100,
        "resp_bytes": 200,
        "orig_pkts": 1,
        "resp_pkts": 2,
        "dst_port": 99999,  # Port out of bounds > 65535
    }
    feats = FlowFeatureExtractor.extract_features(raw_dict)
    feats["dst_port"] = 99999
    res = FeatureCompatibilityValidator.validate(feats)
    assert res.is_compatible is False
    assert "dst_port" in res.invalid_features
