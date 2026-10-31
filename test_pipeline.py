# ============================================================
# CYBERSHIELD GPT
# PHASE 1 → PHASE 4
#
# COMPLETE PIPELINE TEST
#
# CSV
# ↓
# PREPROCESSING
# ↓
# FEATURES
# ↓
# RULES
# ↓
# ISOLATION FOREST
# ↓
# COMBINED DETECTION
# ↓
# SQLITE
# ============================================================


# ============================================================
# IMPORTS
# ============================================================

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

from src.database import (
    create_database,
    store_logs,
    store_incident
)


# ============================================================
# STEP 1 — INITIALIZE DATABASE
# ============================================================

print(
    "\n[STEP 1] Initializing database..."
)

create_database()


# ============================================================
# STEP 2 — LOAD + PREPROCESS LOGS
# ============================================================

print(
    "\n[STEP 2] Preprocessing security logs..."
)

df, behavioral_features = preprocess_logs(

    "data/security_logs.csv"

)


print(
    f"Total logs: {len(df)}"
)

print(
    f"Unique IPs: {len(behavioral_features)}"
)


# ============================================================
# STEP 3 — STORE RAW/PROCESSED LOGS
# ============================================================

print(
    "\n[STEP 3] Storing logs in SQLite..."
)

store_logs(df)


# ============================================================
# STEP 4 — RUN SECURITY RULES
# ============================================================

print(
    "\n[STEP 4] Running security rules..."
)

rule_results = run_security_rules(

    df,

    behavioral_features

)


print(
    f"Rule events detected: "
    f"{len(rule_results)}"
)


# ============================================================
# STEP 5 — RUN MACHINE LEARNING
# ============================================================

print(
    "\n[STEP 5] Running Isolation Forest..."
)

ml_results = detect_anomalies(

    behavioral_features

)


print(
    "ML anomaly detection completed."
)


# ============================================================
# STEP 6 — COMBINE RULE + ML
# ============================================================

print(
    "\n[STEP 6] Combining detection results..."
)

incidents = combine_detection_results(

    behavioral_features,

    rule_results,

    ml_results

)


print(
    f"Suspicious incidents: "
    f"{len(incidents)}"
)


# ============================================================
# STEP 7 — STORE INCIDENTS
# ============================================================

print(
    "\n[STEP 7] Storing incidents in SQLite..."
)


incident_ids = []


for incident in incidents:

    incident_id = store_incident(
        incident
    )

    incident_ids.append(
        incident_id
    )


    print(
        "\n----------------------------------------"
    )

    print(
        f"Incident ID: {incident_id}"
    )

    print(
        f"IP Address: "
        f"{incident['ip_address']}"
    )

    print(
        f"Severity: "
        f"{incident['severity']}"
    )

    print(
        f"Security Score: "
        f"{incident['security_score']}"
    )

    print(
        f"Rules: "
        f"{incident['triggered_rules']}"
    )

    print(
        f"ML Anomaly: "
        f"{incident['ml_anomaly']}"
    )


# ============================================================
# STEP 8 — FINAL STATUS
# ============================================================

print(
    "\n========================================"
)

print(
    "CYBERSHIELD GPT PIPELINE COMPLETED"
)

print(
    "========================================"
)