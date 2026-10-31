
# ============================================================
# CYBERSHIELD GPT — MACHINE LEARNING DETECTION
# File: src/ml_detection.py
# ============================================================

from sklearn.ensemble import IsolationForest


ML_FEATURES = [
    "Failed_Login_Count",
    "Login_Frequency",
    "Access_Count",
    "Unique_User_Count",
    "Night_Login_Count",
    "Access_Denied_Count",
]


def detect_anomalies(behavioral_features):
    """
    Detect unusual IP behavior using Isolation Forest.

    Returns a copy of the behavioral features with:
    - ml_prediction: 1 = normal, -1 = anomaly
    - ml_anomaly: True when classified as an anomaly
    - anomaly_score: lower values indicate more unusual observations
    """

    if behavioral_features.empty:
        results = behavioral_features.copy()
        results["ml_prediction"] = []
        results["ml_anomaly"] = []
        results["anomaly_score"] = []
        return results

    results = behavioral_features.copy()

    # Check that all required ML features exist.
    missing_features = [
        feature
        for feature in ML_FEATURES
        if feature not in results.columns
    ]

    if missing_features:
        raise ValueError(
            f"Missing ML features: {missing_features}"
        )

    # Prepare the numeric feature matrix.
    X = results[ML_FEATURES].fillna(0)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.20,
        random_state=42,
    )

    predictions = model.fit_predict(X)

    results["ml_prediction"] = predictions
    results["ml_anomaly"] = results["ml_prediction"] == -1
    results["anomaly_score"] = model.decision_function(X)

    print(
        "[ML] Anomalies detected:",
        int(results["ml_anomaly"].sum()),
    )

    return results
