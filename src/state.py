from typing import Any, TypedDict


class CyberShieldState(TypedDict, total=False):

    # Uploaded dataset
    file_path: str
    upload_filename: str

    # Preprocessing
    logs: Any
    behavioral_features: Any

    # Detection
    rule_results: list
    ml_results: Any
    incidents: list

    # Database
    stored_log_count: int
    stored_incident_ids: list

    # RAG
    rag_results: list

    # LLM agents
    log_analyses: list
    threat_classifications: list
    recommendations: list
    reports: list

    # Final status
    saved_analysis_count: int
    status: str
    error: str