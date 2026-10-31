# ============================================================
# CYBERSHIELD GPT
# STEP 5 — TEST SECURITY LOG DATA
# ============================================================

import pandas as pd

from config import SECURITY_LOG_FILE


# ------------------------------------------------------------
# LOAD SECURITY LOG
# ------------------------------------------------------------

df = pd.read_csv(
    SECURITY_LOG_FILE
)


# ------------------------------------------------------------
# DISPLAY BASIC INFORMATION
# ------------------------------------------------------------

print("\n" + "=" * 60)

print("CYBERSHIELD GPT - SECURITY LOG TEST")

print("=" * 60)

print("\nTotal Logs:", len(df))

print("\nColumns:")

print(df.columns.tolist())

print("\nFirst 5 Records:")

print(df.head())

print("\nEvent Types:")

print(df["event_type"].value_counts())

print("\nLogin Status:")

print(df["status"].value_counts())

print("\nUnique Users:")

print(df["user"].nunique())

print("\nUnique IP Addresses:")

print(df["ip_address"].nunique())