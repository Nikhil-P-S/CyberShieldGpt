
# ============================================================
# CYBERSHIELDGPT - ANALYSIS PROGRESS TRACKER
# ============================================================

import sqlite3
import json
from datetime import datetime, timezone

from config import DATABASE_PATH


# ============================================================
# 1. CREATE PROGRESS TABLE
# ============================================================

def initialize_progress_table():

    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS analysis_jobs (

            job_id TEXT PRIMARY KEY,

            status TEXT NOT NULL,

            phase TEXT,

            message TEXT,

            progress INTEGER DEFAULT 0,

            completed_phases TEXT,

            result TEXT,

            error TEXT,

            created_at TEXT,

            updated_at TEXT
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# 2. CREATE NEW JOB
# ============================================================

def create_analysis_job(job_id):

    now = datetime.now(
        timezone.utc
    ).isoformat()

    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute("""
        INSERT INTO analysis_jobs
        (
            job_id,
            status,
            phase,
            message,
            progress,
            completed_phases,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        job_id,
        "processing",
        "upload",
        "Dataset uploaded successfully.",
        5,
        json.dumps(["upload"]),
        now,
        now
    ))

    connection.commit()
    connection.close()


# ============================================================
# 3. UPDATE PROGRESS
# ============================================================

def update_analysis_progress(
    job_id,
    phase,
    message,
    progress
):

    now = datetime.now(
        timezone.utc
    ).isoformat()

    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT completed_phases
        FROM analysis_jobs
        WHERE job_id = ?
    """, (job_id,))

    row = cursor.fetchone()

    if row is None:
        connection.close()
        return

    try:
        completed = json.loads(row[0] or "[]")
    except json.JSONDecodeError:
        completed = []

    # A phase marked as complete is retained.
    if phase not in completed and progress >= 100:
        completed.append(phase)

    cursor.execute("""
        UPDATE analysis_jobs
        SET
            status = ?,
            phase = ?,
            message = ?,
            progress = ?,
            completed_phases = ?,
            updated_at = ?
        WHERE job_id = ?
    """, (
        "completed" if progress >= 100 else "processing",
        phase,
        message,
        progress,
        json.dumps(completed),
        now,
        job_id
    ))

    connection.commit()
    connection.close()


# ============================================================
# 4. MARK JOB AS FAILED
# ============================================================

def fail_analysis_job(job_id, error_message):

    now = datetime.now(
        timezone.utc
    ).isoformat()

    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute("""
        UPDATE analysis_jobs
        SET
            status = 'failed',
            message = 'Dataset analysis failed.',
            error = ?,
            updated_at = ?
        WHERE job_id = ?
    """, (
        str(error_message)[:2000],
        now,
        job_id
    ))

    connection.commit()
    connection.close()


# ============================================================
# 5. MARK JOB AS COMPLETED
# ============================================================

def complete_analysis_job(job_id, result=None):

    now = datetime.now(
        timezone.utc
    ).isoformat()

    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute("""
        UPDATE analysis_jobs
        SET
            status = 'completed',
            phase = 'completed',
            message = 'Dataset analysis completed successfully.',
            progress = 100,
            result = ?,
            updated_at = ?
        WHERE job_id = ?
    """, (
        json.dumps(result, default=str),
        now,
        job_id
    ))

    connection.commit()
    connection.close()


# ============================================================
# 6. GET JOB STATUS
# ============================================================

def get_analysis_progress(job_id):

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM analysis_jobs
        WHERE job_id = ?
    """, (job_id,))

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return None

    result = dict(row)

    try:
        result["completed_phases"] = json.loads(
            result["completed_phases"] or "[]"
        )
    except json.JSONDecodeError:
        result["completed_phases"] = []

    try:
        result["result"] = json.loads(
            result["result"]
        ) if result["result"] else None
    except json.JSONDecodeError:
        result["result"] = None

    return result


# Initialize table when this module is imported.
initialize_progress_table()
