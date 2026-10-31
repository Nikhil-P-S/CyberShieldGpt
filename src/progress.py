
# ============================================================
# CYBERSHIELDGPT — LIVE DATASET ANALYSIS PROGRESS TRACKER
# ============================================================

from datetime import datetime
from threading import RLock, local
from copy import deepcopy


# ============================================================
# GLOBAL PROGRESS STORAGE
# ============================================================

_PROGRESS = {}

_LOCK = RLock()

_JOB_CONTEXT = local()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def current_time():

    return datetime.now().strftime("%H:%M:%S")


def current_timestamp():

    return datetime.now().isoformat()


# ============================================================
# CURRENT JOB ID
# ============================================================

def set_current_job_id(job_id):

    _JOB_CONTEXT.job_id = job_id


def get_current_job_id():

    return getattr(
        _JOB_CONTEXT,
        "job_id",
        None
    )


def clear_current_job_id():

    if hasattr(_JOB_CONTEXT, "job_id"):

        del _JOB_CONTEXT.job_id


# ============================================================
# CREATE PROGRESS
# ============================================================

def create_progress(job_id, filename=""):

    if not job_id:
        return

    with _LOCK:

        _PROGRESS[job_id] = {

            "job_id": job_id,

            "filename": filename,

            "status": "running",

            "stage": "upload",

            "percent": 2,

            "message": "Dataset received. Preparing analysis.",

            "events": [

                {
                    "stage": "upload",

                    "message": "Dataset received.",

                    "time": current_time(),

                    "status": "completed",

                    "percent": 2
                }

            ],

            "updated_at": current_timestamp()

        }

    print(
        f"[PROGRESS] Created job: {job_id}"
    )


# ============================================================
# UPDATE PROGRESS
# ============================================================

def update_progress(
    job_id,
    stage="processing",
    message="Processing dataset.",
    percent=0,
    status="running"
):
    """
    Update the live progress of a dataset analysis.

    Correct usage:

        update_progress(
            job_id,
            "loading_dataset",
            "Loading CSV dataset.",
            20
        )

    Keyword usage:

        update_progress(
            job_id,
            stage="loading_dataset",
            message="Loading CSV dataset.",
            percent=20
        )
    """

    if not job_id:
        return

    # --------------------------------------------------------
    # SAFELY CONVERT PERCENTAGE
    # --------------------------------------------------------

    try:

        percent = int(float(percent))

    except (ValueError, TypeError):

        raise ValueError(
            "Progress percentage must be a valid number."
        )

    percent = max(
        0,
        min(100, percent)
    )

    # --------------------------------------------------------
    # NORMALIZE VALUES
    # --------------------------------------------------------

    stage = str(stage or "processing")

    message = str(message or "Processing.")

    status = str(status or "running")

    # --------------------------------------------------------
    # UPDATE SHARED PROGRESS
    # --------------------------------------------------------

    with _LOCK:

        current = _PROGRESS.get(job_id)

        # A job may not have been registered yet.
        # Do not crash the application in that situation.

        if current is None:

            print(
                f"[PROGRESS] Unknown job: {job_id}"
            )

            return

        # ----------------------------------------------------
        # NEVER MOVE PROGRESS BACKWARDS
        # ----------------------------------------------------

        if status == "completed":

            percent = 100

        else:

            percent = max(
                current["percent"],
                percent
            )

        # ----------------------------------------------------
        # UPDATE CURRENT STATE
        # ----------------------------------------------------

        current["stage"] = stage

        current["message"] = message

        current["percent"] = percent

        current["status"] = status

        current["updated_at"] = current_timestamp()

        # ----------------------------------------------------
        # ADD EVENT
        # ----------------------------------------------------

        events = current["events"]

        if (
            not events
            or events[-1]["message"] != message
            or events[-1]["stage"] != stage
        ):

            events.append({

                "stage": stage,

                "message": message,

                "time": current_time(),

                "status": status,

                "percent": percent

            })

        # ----------------------------------------------------
        # KEEP ONLY LATEST 30 EVENTS
        # ----------------------------------------------------

        current["events"] = events[-30:]

    print(
        f"[PROGRESS] {percent}% | {stage} | {message}"
    )


# ============================================================
# GET PROGRESS
# ============================================================

def get_progress(job_id):

    if not job_id:
        return None

    with _LOCK:

        item = _PROGRESS.get(job_id)

        if item is None:
            return None

        return deepcopy(item)


# ============================================================
# MARK PROGRESS AS FAILED
# ============================================================

def fail_progress(job_id, message):

    if not job_id:
        return

    message = str(message)

    with _LOCK:

        current = _PROGRESS.get(job_id)

        if current is None:
            return

        current["stage"] = "failed"

        current["message"] = message

        current["status"] = "failed"

        current["updated_at"] = current_timestamp()

        current["events"].append({

            "stage": "failed",

            "message": message,

            "time": current_time(),

            "status": "failed",

            "percent": current["percent"]

        })

        current["events"] = current["events"][-30:]

    print(
        f"[PROGRESS] FAILED | {message}"
    )


# ============================================================
# MARK PROGRESS AS COMPLETED
# ============================================================

def complete_progress(job_id, message="Dataset analysis completed successfully."):

    update_progress(
        job_id=job_id,
        stage="completed",
        message=message,
        percent=100,
        status="completed"
    )


# ============================================================
# REMOVE OLD JOB
# ============================================================

def remove_progress(job_id):

    if not job_id:
        return

    with _LOCK:

        _PROGRESS.pop(
            job_id,
            None
        )
