# ============================================================
# CYBERSHIELD GPT
# SQLITE DATABASE MODULE
#
# PURPOSE:
#
# 1. Store security logs
# 2. Store detected incidents
# 3. Store AI analysis
# 4. Store recommendations
# 5. Store generated reports
# 6. Store chatbot history
#
# ============================================================


import sqlite3
import json

from config import DATABASE_PATH


# ============================================================
# 1. DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    # Allows rows to behave like dictionaries
    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# 2. CREATE DATABASE TABLES
# ============================================================

def create_database():

    connection = get_connection()

    cursor = connection.cursor()


    # ========================================================
    # TABLE 1 — SECURITY LOGS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (

            id INTEGER PRIMARY KEY,

            timestamp TEXT NOT NULL,

            user TEXT,

            ip_address TEXT,

            event_type TEXT,

            status TEXT,

            resource TEXT
        )
    """)


    # ========================================================
    # TABLE 2 — DETECTED INCIDENTS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            ip_address TEXT NOT NULL,

            severity TEXT,

            security_score REAL DEFAULT 0,

            triggered_rules TEXT,

            ml_anomaly INTEGER DEFAULT 0,

            anomaly_score REAL,

            failed_login_count INTEGER DEFAULT 0,

            login_frequency INTEGER DEFAULT 0,

            access_count INTEGER DEFAULT 0,

            unique_user_count INTEGER DEFAULT 0,

            night_login_count INTEGER DEFAULT 0,

            access_denied_count INTEGER DEFAULT 0,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # ========================================================
    # TABLE 3 — AI ANALYSIS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id INTEGER NOT NULL,

            threat_type TEXT,

            explanation TEXT,

            historical_context TEXT,

            recommendation TEXT,

            report TEXT,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (incident_id)
                REFERENCES incidents(id)
        )
    """)


    # ========================================================
    # TABLE 4 — CHAT HISTORY
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id INTEGER,

            user_message TEXT,

            assistant_response TEXT,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (incident_id)
                REFERENCES incidents(id)
        )
    """)


    # ========================================================
    # SAVE DATABASE CHANGES
    # ========================================================

    connection.commit()

    connection.close()


    print(
        "SQLite database initialized successfully."
    )


# ============================================================
# 3. STORE SECURITY LOGS
# ============================================================
def store_logs(df):

    connection = get_connection()
    cursor = connection.cursor()

    rows = []

    for _, row in df.iterrows():

        rows.append((
            str(row["timestamp"]),
            str(row["user"]),
            str(row["ip_address"]),
            str(row["event_type"]),
            str(row["status"]),
            str(row["resource"])
        ))

    cursor.executemany(
        """
        INSERT INTO logs
        (
            timestamp,
            user,
            ip_address,
            event_type,
            status,
            resource
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        rows
    )

    connection.commit()
    connection.close()

    print(
        "[DATABASE] Logs stored:",
        len(rows)
    )

    return len(rows)


# ============================================================
# 4. STORE INCIDENT
# ============================================================

def store_incident(incident):

    connection = get_connection()

    cursor = connection.cursor()


    # --------------------------------------------------------
    # Convert Python list to JSON
    # --------------------------------------------------------

    triggered_rules = json.dumps(
        incident.get(
            "triggered_rules",
            []
        )
    )


    # --------------------------------------------------------
    # Convert Boolean to SQLite integer
    # --------------------------------------------------------

    ml_anomaly = int(
        incident.get(
            "ml_anomaly",
            False
        )
    )


    # --------------------------------------------------------
    # INSERT INCIDENT
    # --------------------------------------------------------

    cursor.execute("""
        INSERT INTO incidents
        (
            ip_address,
            severity,
            security_score,
            triggered_rules,
            ml_anomaly,
            anomaly_score,

            failed_login_count,
            login_frequency,
            access_count,
            unique_user_count,
            night_login_count,
            access_denied_count
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        incident.get("ip_address"),

        incident.get("severity"),

        incident.get(
            "security_score",
            0
        ),

        triggered_rules,

        ml_anomaly,

        incident.get(
            "anomaly_score",
            0
        ),

        incident.get(
            "failed_login_count",
            0
        ),

        incident.get(
            "login_frequency",
            0
        ),

        incident.get(
            "access_count",
            0
        ),

        incident.get(
            "unique_user_count",
            0
        ),

        incident.get(
            "night_login_count",
            0
        ),

        incident.get(
            "access_denied_count",
            0
        )
    ))


    incident_id = cursor.lastrowid


    connection.commit()

    connection.close()


    return incident_id


# ============================================================
# 5. STORE AI ANALYSIS
# ============================================================

# ============================================================
# STORE AI ANALYSIS
# CYBERSHIELDGPT
# ============================================================

import json


def convert_to_sqlite_value(value):

    """
    Convert Python objects into SQLite-compatible values.

    Lists and dictionaries are stored as JSON strings.
    Other values are converted safely.
    """

    if value is None:
        return ""

    if isinstance(value, (dict, list)):

        return json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            default=str
        )

    if isinstance(value, (str, int, float)):

        return value

    return str(value)


import json


def store_analysis(
    incident_id,
    threat_type,
    explanation,
    historical_context,
    recommendation,
    report
):

    connection = get_connection()
    cursor = connection.cursor()

    try:

        # Convert structured Python data into strings.
        # SQLite cannot directly store lists or dictionaries.

        values = [
            incident_id,
            threat_type,
            explanation,
            historical_context,
            recommendation,
            report
        ]

        converted_values = []

        for value in values:

            if value is None:
                converted_values.append("")

            elif isinstance(value, (list, dict)):

                converted_values.append(
                    json.dumps(
                        value,
                        ensure_ascii=False,
                        default=str
                    )
                )

            elif isinstance(value, (str, int, float)):

                converted_values.append(value)

            else:

                converted_values.append(str(value))

        print(
            "[DATABASE] Recommendation type:",
            type(recommendation).__name__
        )

        print(
            "[DATABASE] Converted recommendation type:",
            type(converted_values[4]).__name__
        )

        cursor.execute(
            """
            INSERT INTO analysis_results
            (
                incident_id,
                threat_type,
                explanation,
                historical_context,
                recommendation,
                report
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            tuple(converted_values)
        )

        connection.commit()

        print(
            "[DATABASE] AI analysis saved successfully."
        )

        return True

    except Exception as error:

        connection.rollback()

        print(
            "[DATABASE ERROR]",
            str(error)
        )

        raise

    finally:

        connection.close()


# ============================================================
# 6. STORE CHAT HISTORY
# ============================================================

def store_chat(
    user_message,
    assistant_response,
    incident_id=None
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO chat_history
        (
            incident_id,
            user_message,
            assistant_response
        )

        VALUES (?, ?, ?)
    """, (

        incident_id,

        user_message,

        assistant_response
    ))


    connection.commit()

    connection.close()


# ============================================================
# 7. GET ALL INCIDENTS
# ============================================================

def get_all_incidents():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *

        FROM incidents

        ORDER BY id DESC
    """)


    rows = cursor.fetchall()

    connection.close()


    return rows


# ============================================================
# 8. GET INCIDENT BY ID
# ============================================================

def get_incident(
    incident_id
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *

        FROM incidents

        WHERE id = ?
    """, (

        incident_id,
    ))


    row = cursor.fetchone()

    connection.close()


    return row


# ============================================================
# 9. GET AI ANALYSIS
# ============================================================

def get_analysis(
    incident_id
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *

        FROM analysis_results

        WHERE incident_id = ?

        ORDER BY id DESC

        LIMIT 1
    """, (

        incident_id,
    ))


    row = cursor.fetchone()

    connection.close()


    return row