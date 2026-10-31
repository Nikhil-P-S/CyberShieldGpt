# ============================================================
# CYBERSHIELDGPT — LANGGRAPH WORKFLOW
# ============================================================

from langgraph.graph import (
    StateGraph,
    START,
    END
)

from src.state import CyberShieldState

from src.agents import (
    preprocess_node,
    detection_node,
    database_node,
    rag_node,
    optimized_ai_node,
    save_analysis_node,
    finish_node
)

from src.progress import (
    update_progress,
    get_current_job_id
)


# ============================================================
# CONDITIONAL ROUTING
# ============================================================

def route_after_database(state: CyberShieldState):

    incidents = state.get(
        "incidents",
        []
    )

    job_id = get_current_job_id()

    # --------------------------------------------------------
    # INCIDENTS FOUND
    # --------------------------------------------------------

    if incidents:

        update_progress(
            job_id,
            stage="routing",
            message=f"{len(incidents)} incidents detected. Moving to RAG knowledge retrieval.",
            percent=62
        )

        print("\n[GRAPH] Security incidents detected.")

        print("[GRAPH] Routing to RAG.")

        return "rag"

    # --------------------------------------------------------
    # NO INCIDENTS
    # --------------------------------------------------------

    update_progress(
        job_id,
        stage="routing",
        message="No incidents detected. Skipping RAG and AI analysis.",
        percent=85
    )

    print("\n[GRAPH] No security incidents detected.")

    print("[GRAPH] Skipping RAG and AI analysis.")

    return "finish"


# ============================================================
# BUILD GRAPH
# ============================================================

def build_cybershield_graph():

    print("\n[GRAPH] Building CyberShieldGPT workflow...")

    workflow = StateGraph(
        CyberShieldState
    )

    # --------------------------------------------------------
    # REGISTER NODES
    # --------------------------------------------------------

    workflow.add_node(
        "preprocess",
        preprocess_node
    )

    workflow.add_node(
        "detect",
        detection_node
    )

    workflow.add_node(
        "database",
        database_node
    )

    workflow.add_node(
        "rag",
        rag_node
    )

    workflow.add_node(
        "optimized_ai",
        optimized_ai_node
    )

    workflow.add_node(
        "save_analysis",
        save_analysis_node
    )

    workflow.add_node(
        "finish",
        finish_node
    )

    # --------------------------------------------------------
    # WORKFLOW CONNECTIONS
    # --------------------------------------------------------

    workflow.add_edge(
        START,
        "preprocess"
    )

    workflow.add_edge(
        "preprocess",
        "detect"
    )

    workflow.add_edge(
        "detect",
        "database"
    )

    # Conditional routing
    workflow.add_conditional_edges(
        "database",
        route_after_database,
        {
            "rag": "rag",
            "finish": "finish"
        }
    )

    workflow.add_edge(
        "rag",
        "optimized_ai"
    )

    workflow.add_edge(
        "optimized_ai",
        "save_analysis"
    )

    workflow.add_edge(
        "save_analysis",
        "finish"
    )

    workflow.add_edge(
        "finish",
        END
    )

    graph = workflow.compile()

    print("\n[GRAPH] CyberShieldGPT workflow compiled successfully.")

    return graph


# ============================================================
# CREATE GRAPH
# ============================================================

cybershield_graph = build_cybershield_graph()