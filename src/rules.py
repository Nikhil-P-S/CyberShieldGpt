# ============================================================
# CYBERSHIELD GPT
# SECURITY RULE ENGINE
# ============================================================


# ============================================================
# 1. BRUTE FORCE DETECTION
# ============================================================

def detect_brute_force(
    behavioral_features
):

    results = []


    for _, row in behavioral_features.iterrows():

        if row["Failed_Login_Count"] > 5:

            results.append({

                "ip_address":
                    row["ip_address"],

                "rule":
                    "BRUTE_FORCE",

                "severity":
                    "HIGH",

                "reason":
                    "More than 5 failed login attempts detected."
            })


    return results


# ============================================================
# 2. NIGHT LOGIN DETECTION
# ============================================================

def detect_night_login(
    df
):

    results = []


    night_logs = df[
        df["night_login"] == 1
    ]


    for _, row in night_logs.iterrows():

        results.append({

            "ip_address":
                row["ip_address"],

            "rule":
                "NIGHT_LOGIN",

            "severity":
                "MEDIUM",

            "reason":
                "Login activity detected between 12 AM and 5 AM."
        })


    return results


# ============================================================
# 3. ACCESS DENIED DETECTION
# ============================================================

def detect_access_denied(
    behavioral_features
):

    results = []


    for _, row in behavioral_features.iterrows():

        if row["Access_Denied_Count"] >= 3:

            results.append({

                "ip_address":
                    row["ip_address"],

                "rule":
                    "REPEATED_ACCESS_DENIED",

                "severity":
                    "HIGH",

                "reason":
                    "Repeated access denied events detected."
            })


    return results


# ============================================================
# 4. MULTIPLE USERS FROM SAME IP
# ============================================================

def detect_multiple_users(
    behavioral_features
):

    results = []


    for _, row in behavioral_features.iterrows():

        if row["Unique_User_Count"] >= 5:

            results.append({

                "ip_address":
                    row["ip_address"],

                "rule":
                    "MULTIPLE_USERS_SAME_IP",

                "severity":
                    "HIGH",

                "reason":
                    "Multiple user accounts accessed from one IP."
            })


    return results


# ============================================================
# 5. HIGH ACTIVITY
# ============================================================

def detect_high_activity(

    behavioral_features,

    threshold=10

):

    results = []


    for _, row in behavioral_features.iterrows():

        if row["Access_Count"] > threshold:

            results.append({

                "ip_address":
                    row["ip_address"],

                "rule":
                    "HIGH_ACTIVITY",

                "severity":
                    "MEDIUM",

                "reason":
                    "Unusually high activity detected from IP."
            })


    return results


# ============================================================
# 6. RUN ALL SECURITY RULES
# ============================================================

def run_security_rules(

    df,

    behavioral_features

):

    all_results = []


    # --------------------------------------------------------
    # Rule 1
    # --------------------------------------------------------

    all_results.extend(

        detect_brute_force(
            behavioral_features
        )

    )


    # --------------------------------------------------------
    # Rule 2
    # --------------------------------------------------------

    all_results.extend(

        detect_night_login(
            df
        )

    )


    # --------------------------------------------------------
    # Rule 3
    # --------------------------------------------------------

    all_results.extend(

        detect_access_denied(
            behavioral_features
        )

    )


    # --------------------------------------------------------
    # Rule 4
    # --------------------------------------------------------

    all_results.extend(

        detect_multiple_users(
            behavioral_features
        )

    )


    # --------------------------------------------------------
    # Rule 5
    # --------------------------------------------------------

    all_results.extend(

        detect_high_activity(
            behavioral_features
        )

    )


    return all_results