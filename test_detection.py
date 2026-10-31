# ============================================================
# CYBERSHIELD GPT
# STEP 19 — TEST COMBINED DETECTION
# ============================================================

from config import SECURITY_LOG_FILE

from src.preprocessing import (
    preprocess_logs
)

from src.rules import (
    run_security_rules
)

from src.ml_detection import (
    detect_anomalies
)

from src.detection import (
    combine_detection_results
)


# ============================================================
# STEP 1 — PREPROCESS
# ============================================================

df, behavioral_features = preprocess_logs(
    SECURITY_LOG_FILE
)


# ============================================================
# STEP 2 — RULE ENGINE
# ============================================================

rule_results = run_security_rules(
    df,
    behavioral_features
)


# ============================================================
# STEP 3 — MACHINE LEARNING
# ============================================================

ml_results = detect_anomalies(
    behavioral_features
)


# ============================================================
# STEP 4 — COMBINE RESULTS
# ============================================================

incidents = combine_detection_results(

    behavioral_features,

    rule_results,

    ml_results

)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 60)

print("FINAL SECURITY DETECTION")

print("=" * 60)


for incident in incidents:

    print(
        f"\nIP: {incident['ip_address']}"
    )

    print(
        f"Severity: {incident['severity']}"
    )

    print(
        f"ML Anomaly: {incident['ml_anomaly']}"
    )

    print(
        f"Rules: {incident['triggered_rules']}"
    )