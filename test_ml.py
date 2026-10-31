# ============================================================
# CYBERSHIELD GPT
# STEP 16 — TEST MACHINE LEARNING
# ============================================================

from config import SECURITY_LOG_FILE

from src.preprocessing import (
    preprocess_logs
)

from src.ml_detection import (
    detect_anomalies
)


# ============================================================
# PREPROCESS
# ============================================================

df, behavioral_features = preprocess_logs(
    SECURITY_LOG_FILE
)


# ============================================================
# RUN ML
# ============================================================

ml_results = detect_anomalies(
    behavioral_features
)


# ============================================================
# DISPLAY SUMMARY
# ============================================================

print("\n" + "=" * 60)

print("ML SUMMARY")

print("=" * 60)

print(
    ml_results[
        [
            "ip_address",
            "ml_prediction",
            "ml_anomaly",
            "anomaly_score"
        ]
    ]
)