"""Feature compatibility layer and validation engine."""

import math
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from threatsense.features.schema import CANONICAL_FEATURES, FEATURE_NAMES, FEATURE_SCHEMA_VERSION


class FeatureCompatibilityResult(BaseModel):
    is_compatible: bool
    status_code: str  # "COMPATIBLE", "FEATURE_SCHEMA_INCOMPATIBLE", "OUT_OF_BOUNDS_WARNING"
    schema_version: str = FEATURE_SCHEMA_VERSION
    missing_features: List[str] = Field(default_factory=list)
    invalid_features: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    message: str


class FeatureCompatibilityValidator:
    """Validates feature vectors against canonical schema specifications before ML inference."""

    @staticmethod
    def validate(feature_dict: Dict[str, Any]) -> FeatureCompatibilityResult:
        missing = []
        invalid = []
        details = {}

        for spec in CANONICAL_FEATURES:
            if spec.name not in feature_dict:
                missing.append(spec.name)
                continue

            val = feature_dict[spec.name]

            # Null check
            if val is None:
                invalid.append(spec.name)
                details[spec.name] = "Value is None"
                continue

            # Type and finiteness check
            try:
                num_val = float(val)
                if math.isnan(num_val) or math.isinf(num_val):
                    invalid.append(spec.name)
                    details[spec.name] = "Value is NaN or Infinite"
                    continue
            except (ValueError, TypeError):
                invalid.append(spec.name)
                details[spec.name] = f"Cannot coerce '{val}' to numeric type"
                continue

            # Domain boundary check (negative values where strictly prohibited)
            if num_val < spec.min_val:
                invalid.append(spec.name)
                details[spec.name] = f"Value {num_val} below minimum {spec.min_val}"
                continue

            # Check port limits
            if spec.name == "dst_port" and (num_val < 0 or num_val > 65535):
                invalid.append(spec.name)
                details[spec.name] = f"Port {num_val} outside [0, 65535] range"
                continue

        if missing or invalid:
            return FeatureCompatibilityResult(
                is_compatible=False,
                status_code="FEATURE_SCHEMA_INCOMPATIBLE",
                missing_features=missing,
                invalid_features=invalid,
                details=details,
                message=f"Feature compatibility check failed: missing {len(missing)} features, {len(invalid)} invalid features.",
            )

        return FeatureCompatibilityResult(
            is_compatible=True,
            status_code="COMPATIBLE",
            missing_features=[],
            invalid_features=[],
            details={"feature_count": len(FEATURE_NAMES)},
            message="Feature vector matches canonical schema successfully.",
        )
