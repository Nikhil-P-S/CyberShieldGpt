import pandas as pd


REQUIRED_COLUMNS = [
    "timestamp",
    "user",
    "ip_address",
    "event_type",
    "status",
    "resource"
]


def load_logs(file_path):

    print("\n[LOG PROCESSING] Loading security logs...")

    df = pd.read_csv(file_path)

    print("[LOG PROCESSING] Logs loaded:", len(df))

    return df


def validate_logs(df):

    print("\n[LOG PROCESSING] Validating log structure...")

    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    if df.empty:
        raise ValueError("The uploaded CSV is empty.")

    print("[LOG PROCESSING] Validation successful.")

    return df


def remove_duplicates(df):

    before = len(df)

    df = df.drop_duplicates().copy()

    after = len(df)

    print(
        f"\n[LOG PROCESSING] Duplicate logs removed: "
        f"{before - after}"
    )

    return df


def handle_missing_values(df):

    print("\n[LOG PROCESSING] Handling missing values...")

    df = df.copy()

    critical_columns = [
        "timestamp",
        "user",
        "ip_address",
        "event_type",
        "status"
    ]

    df = df.dropna(
        subset=critical_columns
    )

    df["resource"] = (
        df["resource"].fillna("Unknown")
    )

    return df


def process_timestamp(df):

    print("\n[LOG PROCESSING] Processing timestamps...")

    df = df.copy()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["timestamp"]
    )

    df["date"] = df["timestamp"].dt.date

    df["hour"] = df["timestamp"].dt.hour

    df["day_of_week"] = (
        df["timestamp"].dt.day_name()
    )

    return df


def create_security_features(df):

    print("\n[LOG PROCESSING] Creating security features...")

    df = df.copy()

    df["failed_login"] = (
        (df["event_type"].str.lower() == "login") &
        (df["status"].str.lower() == "failed")
    ).astype(int)

    df["successful_login"] = (
        (df["event_type"].str.lower() == "login") &
        (df["status"].str.lower() == "success")
    ).astype(int)

    df["access_denied"] = (
        (df["event_type"].str.lower() == "access") &
        (df["status"].str.lower() == "deny")
    ).astype(int)

    df["night_login"] = (
        (df["event_type"].str.lower() == "login") &
        (df["hour"].between(0, 5))
    ).astype(int)

    df["admin_activity"] = (
        df["resource"]
        .str.lower()
        .str.contains("admin", na=False)
    ).astype(int)

    df["security_event"] = (
        (df["failed_login"] == 1) |
        (df["access_denied"] == 1) |
        (df["night_login"] == 1)
    ).astype(int)

    return df


def create_behavioral_features(df):

    print("\n[ML] Creating behavioral features...")

    df = df.copy()

    df["login_event"] = (
        df["event_type"]
        .str.lower()
        .eq("login")
        .astype(int)
    )

    ip_features = (
        df.groupby("ip_address")
        .agg(
            Failed_Login_Count=(
                "failed_login",
                "sum"
            ),

            Login_Frequency=(
                "login_event",
                "sum"
            ),

            Access_Count=(
                "event_type",
                "count"
            ),

            Unique_User_Count=(
                "user",
                "nunique"
            ),

            Night_Login_Count=(
                "night_login",
                "sum"
            ),

            Access_Denied_Count=(
                "access_denied",
                "sum"
            )
        )
        .reset_index()
    )

    print("[ML] Behavioral features created.")

    return ip_features


def preprocess_logs(file_path):

    print("\n" + "=" * 60)
    print("CYBERSHIELD GPT - PREPROCESSING")
    print("=" * 60)

    df = load_logs(file_path)

    df = validate_logs(df)

    df = remove_duplicates(df)

    df = handle_missing_values(df)

    df = process_timestamp(df)

    df = create_security_features(df)

    behavioral_features = (
        create_behavioral_features(df)
    )

    # CSV ID is optional.
    # Generate an internal ID when it is absent.
    if "id" not in df.columns:
        df["id"] = range(1, len(df) + 1)

    df = df.sort_values(
        by="timestamp"
    ).reset_index(drop=True)

    print("\n[LOG PROCESSING] Preprocessing completed.")

    print(
        "[LOG PROCESSING] Final records:",
        len(df)
    )

    return df, behavioral_features