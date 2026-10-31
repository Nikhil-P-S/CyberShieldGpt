import os
import sqlite3
import subprocess
import sys
import uuid
import json

from pathlib import Path
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
    send_file,
)

from werkzeug.utils import secure_filename

from config import DATABASE_PATH

from src.progress import (
    create_progress,
    update_progress,
    get_progress,
    fail_progress,
    set_current_job_id,
    clear_current_job_id,
)


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = Path(DATABASE_PATH)

if not DB_PATH.is_absolute():
    DB_PATH = BASE_DIR / DB_PATH

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "local-dev-change-this",
)

# Maximum uploaded file size: 16 MB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


# ============================================================
# DATABASE HELPERS
# ============================================================

def get_connection():
    """
    Open a read-only connection to the existing SQLite database.
    """

    if not DB_PATH.exists():

        raise FileNotFoundError(
            f"Database not found: {DB_PATH}. "
            "Run python run_pipeline.py first."
        )

    connection = sqlite3.connect(
        f"file:{DB_PATH.as_posix()}?mode=ro",
        uri=True,
        timeout=10,
    )

    connection.row_factory = sqlite3.Row

    return connection


def get_tables(connection):
    """Return existing database table names."""

    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()

    return {
        row["name"]
        for row in rows
    }


def quote_identifier(identifier):
    """Safely quote a database table or column name."""

    return '"' + str(identifier).replace('"', '""') + '"'


def get_columns(connection, table):
    """Return column names for an existing table."""

    if table not in get_tables(connection):
        return []

    return [
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({quote_identifier(table)})"
        ).fetchall()
    ]


def get_primary_key(connection, table):
    """Find the primary key of a table."""

    for row in connection.execute(
        f"PRAGMA table_info({quote_identifier(table)})"
    ).fetchall():

        if row["pk"]:
            return row["name"]

    columns = get_columns(connection, table)

    if "id" in columns:
        return "id"

    return columns[0] if columns else None


def get_rows(connection, table, limit=100):
    """Retrieve rows without assuming a fixed schema."""

    if table not in get_tables(connection):
        return [], []

    columns = get_columns(connection, table)

    if not columns:
        return [], []

    primary_key = get_primary_key(
        connection,
        table,
    )

    order_by = (
        f" ORDER BY {quote_identifier(primary_key)} DESC"
        if primary_key
        else ""
    )

    rows = connection.execute(
        f"""
        SELECT *
        FROM {quote_identifier(table)}
        {order_by}
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return columns, [
        dict(row)
        for row in rows
    ]


def count_rows(connection, table):
    """Count records in a table if it exists."""

    if table not in get_tables(connection):
        return 0

    return connection.execute(
        f"SELECT COUNT(*) FROM {quote_identifier(table)}"
    ).fetchone()[0]


# ============================================================
# DATASET ANALYSIS HISTORY
# ============================================================

def get_write_connection():
    """
    Open a writable SQLite connection.

    Existing get_connection() is read-only.
    This connection is used only for history management.
    """

    if not DB_PATH.exists():

        raise FileNotFoundError(
            f"Database not found: {DB_PATH}"
        )

    connection = sqlite3.connect(
        str(DB_PATH),
        timeout=20,
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# CREATE HISTORY TABLE
# ============================================================

def initialize_dataset_history():

    connection = get_write_connection()

    try:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS dataset_analysis_runs
            (
                id TEXT PRIMARY KEY,

                dataset_filename TEXT NOT NULL,

                created_at TEXT NOT NULL,

                status TEXT,

                total_logs INTEGER DEFAULT 0,

                rule_count INTEGER DEFAULT 0,

                ml_count INTEGER DEFAULT 0,

                incident_count INTEGER DEFAULT 0,

                saved_incident_count INTEGER DEFAULT 0,

                saved_analysis_count INTEGER DEFAULT 0,

                results_json TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_dataset_runs_created_at
            ON dataset_analysis_runs(created_at)
            """
        )

        connection.commit()

        print(
            "[HISTORY] Dataset history table initialized."
        )

    finally:

        connection.close()


# ============================================================
# SAVE ONE COMPLETED DATASET ANALYSIS
# ============================================================

def save_dataset_history(dataset_filename, results):

    initialize_dataset_history()

    run_id = uuid.uuid4().hex

    created_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    results_json = json.dumps(
        results,
        ensure_ascii=False,
        default=str,
    )

    connection = get_write_connection()

    try:

        connection.execute(
            """
            INSERT INTO dataset_analysis_runs
            (
                id,
                dataset_filename,
                created_at,
                status,
                total_logs,
                rule_count,
                ml_count,
                incident_count,
                saved_incident_count,
                saved_analysis_count,
                results_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                dataset_filename,
                created_at,
                str(results.get("status", "completed")),
                int(results.get("total_logs", 0)),
                int(results.get("rule_count", 0)),
                int(results.get("ml_count", 0)),
                int(results.get("incident_count", 0)),
                int(results.get("saved_incident_count", 0)),
                int(results.get("saved_analysis_count", 0)),
                results_json,
            ),
        )

        connection.commit()

        print(
            "[HISTORY] Dataset analysis saved:",
            run_id,
        )

        return run_id

    finally:

        connection.close()


# ============================================================
# GET ONE DATASET HISTORY RECORD
# ============================================================

def get_dataset_history_record(run_id):

    initialize_dataset_history()

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT *
            FROM dataset_analysis_runs
            WHERE id = ?
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()

        return dict(row) if row else None

    finally:

        connection.close()


# ============================================================
# FORMAT JSON DATA SAFELY
# ============================================================

def parse_history_json(value):

    if not value:
        return []

    if isinstance(value, (list, dict)):
        return value

    try:

        return json.loads(value)

    except (json.JSONDecodeError, TypeError):

        return value


def find_value(record, *names, default="—"):
    """Get a value by column name without case sensitivity."""

    if not record:
        return default

    values = {
        str(key).lower(): value
        for key, value in record.items()
    }

    for name in names:

        value = values.get(name.lower())

        if value is not None and value != "":
            return value

    return default


# ============================================================
# HELPER: CHECK AJAX REQUEST
# ============================================================

def is_ajax_request():
    """
    Identify requests made by the live-progress JavaScript.

    The updated dataset_analysis.html sends the
    X-Requested-With header.
    """

    return (
        request.headers.get("X-Requested-With")
        == "XMLHttpRequest"
    )


# ============================================================
# HELPER: RETURN DATASET ANALYSIS ERROR
# ============================================================

def dataset_analysis_error(message, status_code=400):
    """
    Return errors in JSON for AJAX requests.
    Use Flask flash messages for normal form submissions.
    """

    if is_ajax_request():

        return jsonify({
            "success": False,
            "error": str(message),
        }), status_code

    flash(
        str(message),
        "error",
    )

    return redirect(
        url_for("dataset_analysis")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    try:

        with get_connection() as connection:

            tables = get_tables(connection)

            log_count = count_rows(
                connection,
                "logs",
            )

            incident_count = count_rows(
                connection,
                "incidents",
            )

            analysis_count = count_rows(
                connection,
                "analysis_results",
            )

            _, incidents = get_rows(
                connection,
                "incidents",
                limit=10,
            )

            _, logs = get_rows(
                connection,
                "logs",
                limit=10,
            )

            severity_counts = {
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            }

            if "incidents" in tables:

                columns = get_columns(
                    connection,
                    "incidents",
                )

                severity_column = next(
                    (
                        column
                        for column in columns
                        if column.lower() == "severity"
                    ),
                    None,
                )

                if severity_column:

                    results = connection.execute(
                        f"""
                        SELECT
                            UPPER(
                                {quote_identifier(severity_column)}
                            ),
                            COUNT(*)
                        FROM incidents
                        GROUP BY UPPER(
                            {quote_identifier(severity_column)}
                        )
                        """
                    ).fetchall()

                    for severity, count in results:

                        if severity in severity_counts:
                            severity_counts[severity] = count

            return render_template(
                "dashboard.html",
                log_count=log_count,
                incident_count=incident_count,
                analysis_count=analysis_count,
                incidents=incidents,
                logs=logs,
                severity_counts=severity_counts,
                tables=tables,
                database_path=str(DB_PATH),
            )

    except (sqlite3.Error, FileNotFoundError) as exc:

        app.logger.exception(
            "Dashboard database error"
        )

        return render_template(
            "dashboard.html",
            log_count=0,
            incident_count=0,
            analysis_count=0,
            incidents=[],
            logs=[],
            severity_counts={
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
            tables=set(),
            database_path=str(DB_PATH),
            database_error=str(exc),
        )


# ============================================================
# SECURITY LOGS
# ============================================================

@app.route("/logs")
def logs_page():

    try:

        with get_connection() as connection:

            if "logs" not in get_tables(connection):

                return render_template(
                    "logs.html",
                    columns=[],
                    rows=[],
                    error=(
                        "The logs table does not exist. "
                        "Run python run_pipeline.py first."
                    ),
                )

            columns, rows = get_rows(
                connection,
                "logs",
                limit=200,
            )

        return render_template(
            "logs.html",
            columns=columns,
            rows=rows,
            error=None,
        )

    except (sqlite3.Error, FileNotFoundError) as exc:

        app.logger.exception(
            "Unable to load security logs"
        )

        return render_template(
            "logs.html",
            columns=[],
            rows=[],
            error=str(exc),
        )


# ============================================================
# INCIDENT LIST
# ============================================================

@app.route("/incidents")
def incidents_page():

    try:

        with get_connection() as connection:

            columns, rows = get_rows(
                connection,
                "incidents",
                limit=200,
            )

            primary_key = (
                get_primary_key(connection, "incidents")
                if "incidents" in get_tables(connection)
                else None
            )

        return render_template(
            "incidents.html",
            columns=columns,
            rows=rows,
            primary_key=primary_key,
        )

    except (sqlite3.Error, FileNotFoundError) as exc:

        app.logger.exception(
            "Unable to load incidents"
        )

        flash(
            f"Unable to load incidents: {exc}",
            "error",
        )

        return render_template(
            "incidents.html",
            columns=[],
            rows=[],
            primary_key=None,
        )


# ============================================================
# INCIDENT DETAILS
# ============================================================

@app.route("/incidents/<int:incident_id>")
def incident_detail(incident_id):

    try:

        with get_connection() as connection:

            if "incidents" not in get_tables(connection):
                abort(404)

            primary_key = get_primary_key(
                connection,
                "incidents",
            )

            if not primary_key:
                abort(404)

            row = connection.execute(
                f"""
                SELECT *
                FROM incidents
                WHERE {quote_identifier(primary_key)} = ?
                LIMIT 1
                """,
                (incident_id,),
            ).fetchone()

            if row is None:
                abort(404)

            incident = dict(row)

            analyses = []

            if "analysis_results" in get_tables(connection):

                columns = get_columns(
                    connection,
                    "analysis_results",
                )

                foreign_key = next(
                    (
                        column
                        for column in columns
                        if column.lower()
                        in {"incident_id", "incidentid"}
                    ),
                    None,
                )

                if foreign_key:

                    analyses = [
                        dict(item)
                        for item in connection.execute(
                            f"""
                            SELECT *
                            FROM analysis_results
                            WHERE {quote_identifier(foreign_key)} = ?
                            ORDER BY rowid DESC
                            """,
                            (incident_id,),
                        ).fetchall()
                    ]

        return render_template(
            "incident_detail.html",
            incident=incident,
            analyses=analyses,
        )

    except (sqlite3.Error, FileNotFoundError) as exc:

        app.logger.exception(
            "Unable to load incident detail"
        )

        flash(
            f"Unable to load incident: {exc}",
            "error",
        )

        return redirect(
            url_for("incidents_page")
        )


# ============================================================
# RAG RETRIEVAL FOR SECURITY CHAT
# ============================================================

def retrieve_chat_context(question, k=4):
    """
    Use the existing project's RAG implementation.

    Expected functions in src/rag.py:
        search_knowledge(query, k=3)
        format_rag_results(results)
    """

    from src.rag import (
        search_knowledge,
        format_rag_results,
    )

    documents = search_knowledge(
        question,
        k=k,
    )

    context = format_rag_results(documents)

    sources = []

    for document in documents:

        metadata = getattr(
            document,
            "metadata",
            {},
        ) or {}

        source = (
            metadata.get("source")
            or metadata.get("file_name")
            or metadata.get("title")
            or "Cybersecurity knowledge base"
        )

        source = str(source)

        if source not in sources:
            sources.append(source)

    return context, sources


# ============================================================
# GROQ ANSWER GENERATION
# ============================================================

def generate_security_chat_answer(question, history):
    """
    Retrieve knowledge first, then generate an answer using Groq.
    """

    from config import GROQ_API_KEY, GROQ_MODEL

    api_key = (
        os.getenv("GROQ_API_KEY")
        or GROQ_API_KEY
    )

    model_name = (
        os.getenv("GROQ_MODEL")
        or GROQ_MODEL
    )

    if not api_key:

        raise RuntimeError(
            "GROQ_API_KEY is missing. Add it to your .env file."
        )

    # Step 1: Retrieve relevant knowledge from Chroma.

    context, sources = retrieve_chat_context(
        question,
        k=4,
    )

    if not context or not str(context).strip():

        return (
            "I could not find relevant information in the security "
            "knowledge base for this question. Try asking about "
            "brute-force attacks, suspicious logins, credential "
            "stuffing, unauthorized access, or privilege escalation.",
            sources,
        )

    # Step 2: Build the LLM with the configured Groq model.

    from langchain_groq import ChatGroq

    from langchain_core.messages import (
        SystemMessage,
        HumanMessage,
        AIMessage,
    )

    llm = ChatGroq(
        api_key=api_key,
        model=model_name,
        temperature=0.2,
    )

    system_prompt = f"""
You are CyberShieldGPT, a defensive cybersecurity assistant.

Answer the user's question using the retrieved cybersecurity
knowledge below.

Instructions:
1. Prioritize facts supported by the retrieved context.
2. If the context does not support a claim, say so clearly.
3. Explain relevant detection indicators and investigation steps.
4. Recommend defensive containment and prevention measures.
5. Never claim that you executed a security action.
6. Do not provide instructions for stealing credentials,
   attacking real systems, or evading detection.
7. Use clear headings and practical steps.
8. Remind the user to verify important actions against original
   logs and their organization's security policies.

RETRIEVED KNOWLEDGE:
{str(context)[:12000]}
"""

    messages = [
        SystemMessage(content=system_prompt)
    ]

    # Include a small amount of conversation history.

    for item in history[-4:]:

        if item.get("role") == "user":

            messages.append(
                HumanMessage(
                    content=item.get("content", "")[:700]
                )
            )

        elif item.get("role") == "assistant":

            messages.append(
                AIMessage(
                    content=item.get("content", "")[:900]
                )
            )

    messages.append(
        HumanMessage(
            content=question[:2000]
        )
    )

    # Step 3: Generate the answer.

    response = llm.invoke(messages)

    answer = response.content

    if isinstance(answer, list):

        answer = "\n".join(
            str(part.get("text", part))
            if isinstance(part, dict)
            else str(part)
            for part in answer
        )

    return str(answer), sources


# ============================================================
# SECURITY CHAT INTERFACE
# ============================================================

@app.route("/chat", methods=["GET", "POST"])
def chat_page():

    history = session.get(
        "cybershield_chat_history",
        [],
    )

    if request.method == "POST":

        action = request.form.get(
            "action",
            "send",
        )

        if action == "clear":

            session.pop(
                "cybershield_chat_history",
                None,
            )

            return redirect(
                url_for("chat_page")
            )

        question = request.form.get(
            "question",
            "",
        ).strip()

        if not question:

            flash(
                "Please enter a cybersecurity question.",
                "error",
            )

            return redirect(
                url_for("chat_page")
            )

        question = question[:2000]

        # Read earlier messages before adding the new question.

        previous_history = history[-4:]

        history.append({
            "role": "user",
            "content": question,
            "sources": [],
        })

        try:

            answer, sources = generate_security_chat_answer(
                question,
                previous_history,
            )

            history.append({
                "role": "assistant",
                "content": answer[:1800],
                "sources": sources[:5],
            })

        except Exception:

            app.logger.exception(
                "RAG security chat failed"
            )

            history.append({
                "role": "assistant",
                "content": (
                    "I couldn't generate an answer. Check your "
                    "Groq API configuration, model name, installed "
                    "packages, Chroma database, and the functions "
                    "in src/rag.py. See the Flask terminal for "
                    "the technical error."
                ),
                "sources": [],
            })

        # Keep session data bounded because Flask's default
        # session is stored in a signed browser cookie.

        session["cybershield_chat_history"] = history[-6:]

        session.modified = True

        return redirect(
            url_for("chat_page")
        )

    return render_template(
        "chat.html",
        history=history,
    )


# ============================================================
# RUN EXISTING LANGGRAPH PIPELINE
# ============================================================

@app.route("/run-analysis", methods=["POST"])
def run_analysis():
    """
    Run the existing pipeline.

    Keep this endpoint local-only unless proper authentication
    and CSRF protection are configured.
    """

    pipeline_path = BASE_DIR / "run_pipeline.py"

    if not pipeline_path.exists():

        flash(
            "run_pipeline.py was not found.",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    try:

        result = subprocess.run(
            [
                sys.executable,
                str(pipeline_path),
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )

        if result.returncode == 0:

            flash(
                "Security analysis completed successfully.",
                "success",
            )

        else:

            output = (
                result.stderr
                or result.stdout
                or ""
            )[-1800:]

            flash(
                f"Pipeline failed: {output}",
                "error",
            )

    except subprocess.TimeoutExpired:

        flash(
            "Pipeline timed out after 10 minutes.",
            "error",
        )

    except OSError as exc:

        flash(
            f"Could not start the pipeline: {exc}",
            "error",
        )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# DATASET UPLOAD CONFIGURATION
# ============================================================

UPLOAD_DIR = BASE_DIR / "data" / "uploads"

UPLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# LIVE DATASET ANALYSIS PROGRESS API
# ============================================================

# ============================================================
# LIVE DATASET ANALYSIS PROGRESS API
# ============================================================

@app.route(
    "/dataset-analysis/progress/<string:job_id>",
    methods=["GET"],
)
def dataset_analysis_progress(job_id):

    """
    Return live progress information.

    IMPORTANT:
    If the frontend requests progress before the POST request
    creates the job, return a waiting response instead of 404.
    """

    progress = get_progress(job_id)

    if progress is None:

        return jsonify({

            "job_id": job_id,

            "status": "running",

            "stage": "waiting",

            "message": "Waiting for the analysis job to initialize.",

            "percent": 0,

            "events": [],

        }), 200

    return jsonify(progress), 200


# ============================================================
# DATASET ANALYSIS ROUTE
# ============================================================

@app.route(
    "/dataset-analysis",
    methods=["GET", "POST"],
)
def dataset_analysis():

    # --------------------------------------------------------
    # DISPLAY UPLOAD PAGE
    # --------------------------------------------------------

    if request.method == "GET":

        return render_template(
            "dataset_analysis.html",
            results=None,
            filename=None,
        )

    # --------------------------------------------------------
    # GET FRONTEND JOB ID
    # --------------------------------------------------------

    job_id = (
        request.form.get("progress_id", "").strip()
        or uuid.uuid4().hex
    )

    # --------------------------------------------------------
    # CREATE PROGRESS BEFORE PROCESSING
    # --------------------------------------------------------

    uploaded = request.files.get("dataset")

    original_name = ""

    if uploaded and uploaded.filename:

        original_name = secure_filename(
            uploaded.filename
        )

    create_progress(
        job_id,
        filename=original_name
    )

    temp_path = None

    # --------------------------------------------------------
    # START DATASET ANALYSIS
    # --------------------------------------------------------

    try:

        # ====================================================
        # STEP 1 — INITIALIZATION
        # ====================================================

        update_progress(
            job_id,
            "initialization",
            "Initializing dataset analysis.",
            5
        )

        # ====================================================
        # STEP 2 — VALIDATE UPLOAD
        # ====================================================

        if uploaded is None or not uploaded.filename:

            raise ValueError(
                "Please select a CSV dataset."
            )

        original_name = secure_filename(
            uploaded.filename
        )

        if not original_name.lower().endswith(".csv"):

            raise ValueError(
                "Only CSV files are supported."
            )

        update_progress(
            job_id,
            "upload",
            "Dataset file received successfully.",
            10
        )

        # ====================================================
        # STEP 3 — SAVE TEMPORARY FILE
        # ====================================================

        temp_path = UPLOAD_DIR / (
            f"{uuid.uuid4().hex}_{original_name}"
        )

        uploaded.save(temp_path)

        print(
            "\n[FLASK] Dataset uploaded:",
            original_name
        )

        update_progress(
            job_id,
            "loading_dataset",
            "Uploaded dataset saved. Reading CSV file.",
            15
        )

        # ====================================================
        # STEP 4 — VALIDATE CSV
        # ====================================================

        preview = pd.read_csv(
            temp_path,
            nrows=5
        )

        required_columns = {

            "timestamp",
            "user",
            "ip_address",
            "event_type",
            "status",
            "resource",

        }

        missing = sorted(
            required_columns - set(preview.columns)
        )

        if missing:

            raise ValueError(
                "Missing CSV columns: "
                + ", ".join(missing)
            )

        update_progress(
            job_id,
            "data_validation",
            "CSV structure and required columns validated.",
            20
        )

        # ====================================================
        # STEP 5 — BUILD LANGGRAPH
        # ====================================================

        update_progress(
            job_id,
            "graph_initialization",
            "Preparing the CyberShieldGPT LangGraph workflow.",
            25
        )

        from src.graph import build_cybershield_graph

        graph = build_cybershield_graph()

        # ====================================================
        # STEP 6 — INITIALIZE LANGGRAPH STATE
        # ====================================================

        initial_state = {

            "file_path": str(temp_path),

            "upload_filename": original_name,

        }

        # ====================================================
        # STEP 7 — CONNECT JOB ID TO LANGGRAPH
        # ====================================================

        set_current_job_id(job_id)

        update_progress(
            job_id,
            "graph_execution",
            "LangGraph workflow started.",
            30
        )

        print(
            "\n[FLASK] Starting LangGraph workflow."
        )

        # ====================================================
        # STEP 8 — EXECUTE LANGGRAPH
        # ====================================================

        state = graph.invoke(
            initial_state
        )

        print(
            "[FLASK] Graph status:",
            state.get("status")
        )

        # ====================================================
        # STEP 9 — CHECK WORKFLOW STATUS
        # ====================================================

        if state.get("status") == "failed":

            raise RuntimeError(
                state.get(
                    "error",
                    "LangGraph workflow failed."
                )
            )

        update_progress(
            job_id,
            "collecting_results",
            "LangGraph execution completed. Collecting analysis results.",
            85
        )

        # ====================================================
        # STEP 10 — COLLECT WORKFLOW OUTPUTS
        # ====================================================

        logs = state.get("logs")

        rule_results = state.get(
            "rule_results",
            []
        ) or []

        ml_results = state.get(
            "ml_results"
        )

        incidents = state.get(
            "incidents",
            []
        ) or []

        # ====================================================
        # STEP 11 — MAP RAG RESULTS BY IP
        # ====================================================

        rag_by_ip = {

            item["ip_address"]: item

            for item in state.get(
                "rag_results",
                []
            )

        }

        # ====================================================
        # STEP 12 — MAP AI ANALYSES BY IP
        # ====================================================

        analyses_by_ip = {

            item["ip_address"]: item["analysis"]

            for item in state.get(
                "log_analyses",
                []
            )

        }

        # ====================================================
        # STEP 13 — MAP THREAT CLASSIFICATIONS
        # ====================================================

        threats_by_ip = {

            item["ip_address"]: item["threat_type"]

            for item in state.get(
                "threat_classifications",
                []
            )

        }

        # ====================================================
        # STEP 14 — MAP RECOMMENDATIONS
        # ====================================================

        recommendations_by_ip = {

            item["ip_address"]: item["recommendation"]

            for item in state.get(
                "recommendations",
                []
            )

        }

        # ====================================================
        # STEP 15 — MAP REPORTS
        # ====================================================

        reports_by_ip = {

            item["ip_address"]: item["report"]

            for item in state.get(
                "reports",
                []
            )

        }

        # ====================================================
        # STEP 16 — GROUP RULE RESULTS BY IP
        # ====================================================

        rules_by_ip = {}

        for rule in rule_results:

            ip = str(
                rule["ip_address"]
            )

            rules_by_ip.setdefault(
                ip,
                []
            ).append(rule)

        # ====================================================
        # STEP 17 — GROUP ML RESULTS BY IP
        # ====================================================

        ml_by_ip = {}

        if ml_results is not None:

            for _, row in ml_results.iterrows():

                ml_by_ip[
                    str(row["ip_address"])
                ] = row.to_dict()

        # ====================================================
        # STEP 18 — CREATE INCIDENT CARDS
        # ====================================================

        incident_cards = []

        incident_ids = state.get(
            "stored_incident_ids",
            []
        ) or []

        for index, incident in enumerate(incidents):

            ip = str(
                incident["ip_address"]
            )

            incident_id = (
                incident_ids[index]
                if index < len(incident_ids)
                else None
            )

            rag = rag_by_ip.get(
                ip,
                {}
            )

            incident_cards.append({

                "incident_id": incident_id,

                "ip_address": ip,

                "severity": incident.get(
                    "severity",
                    "LOW"
                ),

                "security_score": incident.get(
                    "security_score",
                    0
                ),

                "ml_anomaly": bool(
                    incident.get(
                        "ml_anomaly",
                        False
                    )
                ),

                "anomaly_score": incident.get(
                    "anomaly_score"
                ),

                "triggered_rules": incident.get(
                    "triggered_rules",
                    []
                ),

                "rule_details": rules_by_ip.get(
                    ip,
                    []
                ),

                "ml_details": ml_by_ip.get(
                    ip,
                    {}
                ),

                "rag_query": rag.get(
                    "query",
                    ""
                ),

                "rag_context": rag.get(
                    "context",
                    ""
                ),

                "sources": rag.get(
                    "sources",
                    []
                ),

                "log_analysis": analyses_by_ip.get(
                    ip,
                    "Not generated."
                ),

                "threat_classification": threats_by_ip.get(
                    ip,
                    "Not generated."
                ),

                "recommendation": recommendations_by_ip.get(
                    ip,
                    "Not generated."
                ),

                "report": reports_by_ip.get(
                    ip,
                    "Not generated."
                ),

            })

        # ====================================================
        # STEP 19 — CALCULATE SUMMARY
        # ====================================================

        total_logs = (
            int(len(logs))
            if logs is not None
            else 0
        )

        ml_count = 0

        if (
            ml_results is not None
            and len(ml_results) > 0
        ):

            ml_count = int(
                ml_results["ml_anomaly"].sum()
            )

        results = {

            "status": state.get(
                "status",
                "completed"
            ),

            "total_logs": total_logs,

            "rule_count": len(
                rule_results
            ),

            "ml_count": ml_count,

            "incident_count": len(
                incidents
            ),

            "saved_incident_count": len(
                incident_ids
            ),

            "saved_analysis_count": state.get(
                "saved_analysis_count",
                0
            ),

            "incidents": incident_cards,

        }

        # ====================================================
        # STEP 20 — SAVE ANALYSIS HISTORY
        # ====================================================

        update_progress(
            job_id,
            "saving_history",
            "Saving completed analysis to dataset history.",
            92
        )

        history_id = save_dataset_history(
            dataset_filename=original_name,
            results=results
        )

        results["history_id"] = history_id

        print(
            "[FLASK] Dataset history saved:",
            history_id
        )

        # ====================================================
        # STEP 21 — COMPLETE PROGRESS
        # ====================================================

        update_progress(
            job_id,
            "completed",
            "Dataset analysis completed successfully.",
            100,
            status="completed"
        )

        # ====================================================
        # STEP 22 — RENDER RESULTS
        # ====================================================

        rendered_html = render_template(
            "dataset_analysis.html",
            results=results,
            filename=original_name
        )

        # ====================================================
        # STEP 23 — RETURN AJAX RESPONSE
        # ====================================================

        if is_ajax_request():

            return jsonify({

                "success": True,

                "job_id": job_id,

                "html": rendered_html,

                "results": {

                    "total_logs": total_logs,

                    "rule_count": len(rule_results),

                    "ml_count": ml_count,

                    "incident_count": len(incidents),

                    "saved_incident_count": len(incident_ids),

                }

            }), 200

        # Normal form submission.

        return rendered_html

    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as error:

        app.logger.exception(
            "Dataset analysis failed"
        )

        fail_progress(
            job_id,
            str(error)
        )

        if is_ajax_request():

            return jsonify({

                "success": False,

                "job_id": job_id,

                "error": str(error),

            }), 500

        flash(
            f"Dataset analysis failed: {error}",
            "error"
        )

        return redirect(
            url_for("dataset_analysis")
        )

    # ========================================================
    # CLEANUP
    # ========================================================

    finally:

        clear_current_job_id()

        try:

            if temp_path and temp_path.exists():

                temp_path.unlink()

                print(
                    "[FLASK] Temporary dataset removed."
                )

        except OSError:

            app.logger.warning(
                "Could not remove temporary upload."
            )


# ============================================================
# DATASET ANALYSIS HISTORY PAGE
# ============================================================

@app.route("/dataset-analysis/history")
def dataset_analysis_history():

    try:

        initialize_dataset_history()

        with get_connection() as connection:

            rows = connection.execute(
                """
                SELECT
                    id,
                    dataset_filename,
                    created_at,
                    status,
                    total_logs,
                    rule_count,
                    ml_count,
                    incident_count,
                    saved_incident_count,
                    saved_analysis_count
                FROM dataset_analysis_runs
                ORDER BY created_at DESC
                LIMIT 200
                """
            ).fetchall()

            history = [
                dict(row)
                for row in rows
            ]

        return render_template(
            "dataset_analysis_history.html",
            history=history,
        )

    except Exception as error:

        app.logger.exception(
            "Unable to load dataset history"
        )

        flash(
            f"Unable to load dataset history: {error}",
            "error",
        )

        return render_template(
            "dataset_analysis_history.html",
            history=[],
        )


# ============================================================
# DOWNLOAD DATASET ANALYSIS REPORT
# ============================================================

@app.route(
    "/dataset-analysis/history/<string:run_id>/download"
)
def download_dataset_history(run_id):

    try:

        record = get_dataset_history_record(
            run_id
        )

        if record is None:
            abort(404)

        results = json.loads(
            record["results_json"]
        )

        # ----------------------------------------------------
        # CREATE WORD DOCUMENT
        # ----------------------------------------------------

        from docx import Document

        from docx.shared import Inches

        from docx.enum.text import WD_ALIGN_PARAGRAPH

        document = Document()

        section = document.sections[0]

        section.top_margin = Inches(0.7)

        section.bottom_margin = Inches(0.7)

        # ----------------------------------------------------
        # TITLE
        # ----------------------------------------------------

        title = document.add_heading(
            "CYBERSHIELDGPT",
            0,
        )

        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        subtitle = document.add_paragraph(
            "Dataset Security Analysis Report"
        )

        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER

        document.add_paragraph(
            f"Dataset: {record['dataset_filename']}"
        )

        document.add_paragraph(
            f"Analysis ID: {record['id']}"
        )

        document.add_paragraph(
            f"Analysis Date: {record['created_at']}"
        )

        document.add_paragraph(
            f"Status: {record['status']}"
        )

        # ----------------------------------------------------
        # EXECUTIVE SUMMARY
        # ----------------------------------------------------

        document.add_heading(
            "1. Executive Summary",
            level=1,
        )

        summary_table = document.add_table(
            rows=0,
            cols=2,
        )

        summary_table.style = "Light Shading Accent 1"

        summary_items = [

            ("Total Logs", record["total_logs"]),

            ("Rule Findings", record["rule_count"]),

            ("ML Anomalies", record["ml_count"]),

            ("Detected Incidents", record["incident_count"]),

            ("Saved Incidents", record["saved_incident_count"]),

            ("Saved AI Analyses", record["saved_analysis_count"]),

        ]

        for label, value in summary_items:

            cells = summary_table.add_row().cells

            cells[0].text = str(label)

            cells[1].text = str(value)

        # ----------------------------------------------------
        # INCIDENT DETAILS
        # ----------------------------------------------------

        incidents = results.get(
            "incidents",
            [],
        )

        document.add_heading(
            "2. Incident Analysis",
            level=1,
        )

        if not incidents:

            document.add_paragraph(
                "No security incidents were detected in this dataset."
            )

        for index, incident in enumerate(
            incidents,
            start=1,
        ):

            document.add_heading(
                f"Incident {index}",
                level=2,
            )

            document.add_paragraph(
                f"Incident ID: {incident.get('incident_id', 'N/A')}"
            )

            document.add_paragraph(
                f"IP Address: {incident.get('ip_address', 'N/A')}"
            )

            document.add_paragraph(
                f"Severity: {incident.get('severity', 'N/A')}"
            )

            document.add_paragraph(
                f"Security Score: {incident.get('security_score', 'N/A')}"
            )

            document.add_paragraph(
                f"ML Anomaly: {incident.get('ml_anomaly', 'N/A')}"
            )

            # ------------------------------------------------
            # TRIGGERED RULES
            # ------------------------------------------------

            document.add_heading(
                "Triggered Rules",
                level=3,
            )

            rules = incident.get(
                "rule_details",
                [],
            )

            if rules:

                for rule in rules:

                    document.add_paragraph(
                        str(rule),
                        style="List Bullet",
                    )

            else:

                document.add_paragraph(
                    "No rule details available."
                )

            # ------------------------------------------------
            # AI LOG ANALYSIS
            # ------------------------------------------------

            document.add_heading(
                "AI Log Analysis",
                level=3,
            )

            document.add_paragraph(
                str(
                    incident.get(
                        "log_analysis",
                        "Not available",
                    )
                )
            )

            # ------------------------------------------------
            # THREAT CLASSIFICATION
            # ------------------------------------------------

            document.add_heading(
                "Threat Classification",
                level=3,
            )

            document.add_paragraph(
                str(
                    incident.get(
                        "threat_classification",
                        "Not available",
                    )
                )
            )

            # ------------------------------------------------
            # RAG CONTEXT
            # ------------------------------------------------

            document.add_heading(
                "RAG Context",
                level=3,
            )

            document.add_paragraph(
                str(
                    incident.get(
                        "rag_context",
                        "No RAG context available.",
                    )
                )
            )

            sources = incident.get(
                "sources",
                [],
            )

            if sources:

                document.add_paragraph(
                    "Knowledge Sources: "
                    + ", ".join(
                        map(str, sources)
                    )
                )

            # ------------------------------------------------
            # RECOMMENDATIONS
            # ------------------------------------------------

            document.add_heading(
                "Recommended Actions",
                level=3,
            )

            recommendations = parse_history_json(
                incident.get(
                    "recommendation",
                    [],
                )
            )

            if isinstance(recommendations, list):

                for recommendation in recommendations:

                    if isinstance(recommendation, dict):

                        document.add_paragraph(
                            f"Priority: {recommendation.get('priority', 'N/A')}",
                            style="List Bullet",
                        )

                        document.add_paragraph(
                            f"Action: {recommendation.get('action', '')}"
                        )

                        document.add_paragraph(
                            f"Reason: {recommendation.get('reason', '')}"
                        )

                        document.add_paragraph(
                            f"Verification: {recommendation.get('verification', '')}"
                        )

                    else:

                        document.add_paragraph(
                            str(recommendation),
                            style="List Bullet",
                        )

            elif isinstance(recommendations, dict):

                document.add_paragraph(
                    json.dumps(
                        recommendations,
                        ensure_ascii=False,
                        indent=2,
                    )
                )

            else:

                document.add_paragraph(
                    str(recommendations)
                )

            # ------------------------------------------------
            # FINAL INCIDENT REPORT
            # ------------------------------------------------

            document.add_heading(
                "Final Incident Report",
                level=3,
            )

            document.add_paragraph(
                str(
                    incident.get(
                        "report",
                        "Not available",
                    )
                )
            )

            document.add_paragraph(" ")

        # ----------------------------------------------------
        # DISCLAIMER
        # ----------------------------------------------------

        document.add_heading(
            "3. Analysis Limitations",
            level=1,
        )

        document.add_paragraph(
            "This report contains automated security analysis. "
            "ML anomaly detection indicates unusual behavior and "
            "does not independently prove malicious activity. "
            "Recommendations require validation by an authorized "
            "security analyst before operational execution."
        )

        # ----------------------------------------------------
        # EXPORT TO MEMORY
        # ----------------------------------------------------

        output = BytesIO()

        document.save(output)

        output.seek(0)

        safe_filename = secure_filename(
            record["dataset_filename"]
        )

        report_filename = (
            f"CyberShieldGPT_{safe_filename}_report.docx"
        )

        return send_file(
            output,
            as_attachment=True,
            download_name=report_filename,
            mimetype=(
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
        )

    except Exception as error:

        app.logger.exception(
            "Dataset report download failed"
        )

        flash(
            f"Unable to generate report: {error}",
            "error",
        )

        return redirect(
            url_for("dataset_analysis_history")
        )


# ============================================================
# DELETE DATASET HISTORY RECORD
# ============================================================

@app.route(
    "/dataset-analysis/history/<string:run_id>/delete",
    methods=["POST"],
)
def delete_dataset_history(run_id):

    try:

        connection = get_write_connection()

        try:

            cursor = connection.execute(
                """
                DELETE FROM dataset_analysis_runs
                WHERE id = ?
                """,
                (run_id,),
            )

            connection.commit()

            deleted = cursor.rowcount

        finally:

            connection.close()

        if deleted:

            flash(
                "Dataset analysis history deleted successfully.",
                "success",
            )

        else:

            flash(
                "Dataset history record was not found.",
                "error",
            )

    except Exception as error:

        app.logger.exception(
            "Dataset history deletion failed"
        )

        flash(
            f"Unable to delete history: {error}",
            "error",
        )

    return redirect(
        url_for("dataset_analysis_history")
    )


# ============================================================
# TEMPLATE FILTER: JSON
# ============================================================

@app.template_filter("from_json")
def from_json_filter(value):

    if not value:
        return []

    if isinstance(value, (list, dict)):
        return value

    try:

        return json.loads(value)

    except (ValueError, TypeError):

        return []


# ============================================================
# START FLASK
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True,
    )