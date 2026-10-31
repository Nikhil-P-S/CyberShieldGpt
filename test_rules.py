# ============================================================
# CYBERSHIELD GPT
# STEP 12 — TEST RULE ENGINE
# ============================================================

from config import SECURITY_LOG_FILE

from src.preprocessing import (
    preprocess_logs
)

from src.rules import (
    run_security_rules
)


# ============================================================
# PREPROCESS LOGS
# ============================================================

df, behavioral_features = preprocess_logs(
    SECURITY_LOG_FILE
)


# ============================================================
# RUN SECURITY RULES
# ============================================================

rule_results = run_security_rules(
    df,
    behavioral_features
)


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 60)

print("RULE DETECTION SUMMARY")

print("=" * 60)

print(
    "Total rule detections:",
    len(rule_results)
)