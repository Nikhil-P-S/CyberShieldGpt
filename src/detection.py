# ============================================================
# CYBERSHIELD GPT
# COMBINED SECURITY DETECTION
#
# Combines:
#
# 1. Rule-based detection
# 2. Isolation Forest anomaly detection
# 3. Security score
# 4. Incident generation
#
# ============================================================


# ============================================================
# 1. SEVERITY PRIORITY
# ============================================================

SEVERITY_PRIORITY = {

    "LOW": 1,

    "MEDIUM": 2,

    "HIGH": 3,

    "CRITICAL": 4
}


# ============================================================
# 2. RULE SCORES
# ============================================================

RULE_SCORES = {

    "BRUTE_FORCE": 40,

    "NIGHT_LOGIN": 15,

    "REPEATED_ACCESS_DENIED": 25,

    "MULTIPLE_USERS_SAME_IP": 30,

    "HIGH_ACTIVITY": 15
}


# ============================================================
# 3. GET HIGHEST SEVERITY
# ============================================================

def get_highest_severity(
    severities
):

    if not severities:

        return "LOW"


    return max(
        severities,
        key=lambda severity:
            SEVERITY_PRIORITY.get(
                severity,
                0
            )
    )


# ============================================================
# 4. CALCULATE SECURITY SCORE
# ============================================================

def calculate_security_score(
    triggered_rules,
    ml_anomaly
):

    score = 0


    # --------------------------------------------------------
    # Add score for triggered rules
    # --------------------------------------------------------

    for rule in triggered_rules:

        score += RULE_SCORES.get(
            rule,
            0
        )


    # --------------------------------------------------------
    # Add ML anomaly contribution
    # --------------------------------------------------------

    if ml_anomaly:

        score += 20


    # --------------------------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------------------------

    score = min(
        score,
        100
    )


    return score


# ============================================================
# 5. COMBINE RULE + ML RESULTS
# ============================================================

def combine_detection_results(

    behavioral_features,

    rule_results,

    ml_results

):

    incidents = []


    # ========================================================
    # ORGANIZE RULE RESULTS BY IP
    # ========================================================

    rules_by_ip = {}


    for result in rule_results:

        ip = result["ip_address"]

        if ip not in rules_by_ip:

            rules_by_ip[ip] = []


        rules_by_ip[ip].append(
            result
        )


    # ========================================================
    # PROCESS ML RESULTS
    # ========================================================

    for _, row in ml_results.iterrows():

        ip = row["ip_address"]


        # ----------------------------------------------------
        # ML anomaly
        # ----------------------------------------------------

        ml_anomaly = bool(
            row["ml_anomaly"]
        )


        # ----------------------------------------------------
        # Rules triggered for this IP
        # ----------------------------------------------------

        ip_rules = rules_by_ip.get(
            ip,
            []
        )


        triggered_rules = [

            rule["rule"]

            for rule in ip_rules
        ]


        # ----------------------------------------------------
        # Rule severities
        # ----------------------------------------------------

        rule_severities = [

            rule["severity"]

            for rule in ip_rules
        ]


        # ----------------------------------------------------
        # Determine if suspicious
        # ----------------------------------------------------

        suspicious = (

            ml_anomaly

            or

            len(triggered_rules) > 0
        )


        # ----------------------------------------------------
        # Ignore normal IPs
        # ----------------------------------------------------

        if not suspicious:

            continue


        # ====================================================
        # DETERMINE SEVERITY
        # ====================================================

        severity = get_highest_severity(
            rule_severities
        )


        # ----------------------------------------------------
        # ML-only anomaly
        # ----------------------------------------------------

        if (

            ml_anomaly

            and

            not rule_severities

        ):

            severity = "MEDIUM"


        # ====================================================
        # SECURITY SCORE
        # ====================================================

        security_score = calculate_security_score(

            triggered_rules,

            ml_anomaly

        )


        # ====================================================
        # CREATE INCIDENT
        # ====================================================

        incident = {

            "ip_address":
                ip,

            "severity":
                severity,

            "security_score":
                security_score,

            "triggered_rules":
                triggered_rules,

            "ml_anomaly":
                ml_anomaly,

            "anomaly_score":
                float(
                    row["anomaly_score"]
                ),

            # ------------------------------------------------
            # Behavioral features
            # ------------------------------------------------

            "failed_login_count":
                int(
                    row["Failed_Login_Count"]
                ),

            "login_frequency":
                int(
                    row["Login_Frequency"]
                ),

            "access_count":
                int(
                    row["Access_Count"]
                ),

            "unique_user_count":
                int(
                    row["Unique_User_Count"]
                ),

            "night_login_count":
                int(
                    row["Night_Login_Count"]
                ),

            "access_denied_count":
                int(
                    row["Access_Denied_Count"]
                )
        }


        incidents.append(
            incident
        )


    return incidents