# ============================================================
# CYBERSHIELD GPT
# TEST PREPROCESSING + ML FEATURES
# ============================================================

from config import SECURITY_LOG_FILE

from src.preprocessing import preprocess_logs


# ============================================================
# RUN
# ============================================================

df, behavioral_features = preprocess_logs(
    SECURITY_LOG_FILE
)


# ============================================================
# DISPLAY LOGS
# ============================================================

print("\n" + "=" * 60)

print("PROCESSED LOGS")

print("=" * 60)

print(
    df.head(10)
)


# ============================================================
# DISPLAY ML FEATURES
# ============================================================

print("\n" + "=" * 60)

print("BEHAVIORAL FEATURES FOR ML")

print("=" * 60)

print(
    behavioral_features
)