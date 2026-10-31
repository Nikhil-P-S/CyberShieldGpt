
# ============================================================
# CYBERSHIELDGPT
# OPTIMIZED LANGGRAPH WORKFLOW
# ============================================================

from langgraph.graph import StateGraph, START, END

from src.state import CyberShieldState

from src.agents import (
    preprocess_node,
    detection_node,
    database_node,
    rag_node,
    optimized_ai_node,
    save_analysis_node,
    finish_node,
)


# ============================================================
# 1. CONDITIONAL ROUTING
# ============================================================

def route_after_database(state: CyberShieldState):

    """
    Check whether security incidents were detected.

    If incidents exist:
        Continue to RAG and AI analysis.

    If no incidents exist:
        Skip AI processing and finish.
    """

    incidents = state.get("incidents", [])

    if incidents:

        print(
            "\n[GRAPH] Security incidents detected."
        )

        print(
            "[GRAPH] Routing to RAG."
        )

        return "rag"

    print(
        "\n[GRAPH] No security incidents detected."
    )

    print(
        "[GRAPH] Skipping RAG and AI analysis."
    )

    return "finish"


# ============================================================
# 2. BUILD CYBERSHIELD GRAPH
# ============================================================

def build_cybershield_graph():

    print(
        "\n[GRAPH] Building CyberShieldGPT workflow..."
    )

    workflow = StateGraph(CyberShieldState)


    # ========================================================
    # REGISTER NODES
    # ========================================================

    # Step 1: CSV preprocessing
    workflow.add_node(
        "preprocess",
        preprocess_node
    )


    # Step 2: Rule-based and ML detection
    workflow.add_node(
        "detect",
        detection_node
    )


    # Step 3: Save logs and incidents
    workflow.add_node(
        "database",
        database_node
    )


    # Step 4: Retrieve relevant cybersecurity knowledge
    workflow.add_node(
        "rag",
        rag_node
    )


    # Step 5: Combined AI analysis
    # One Groq call per incident
    workflow.add_node(
        "optimized_ai",
        optimized_ai_node
    )


    # Step 6: Save AI analysis and recommendations
    workflow.add_node(
        "save_analysis",
        save_analysis_node
    )


    # Step 7: Finish workflow
    workflow.add_node(
        "finish",
        finish_node
    )


    # ========================================================
    # CONNECT NODES
    # ========================================================

    # START -> PREPROCESS
    workflow.add_edge(
        START,
        "preprocess"
    )


    # PREPROCESS -> DETECTION
    workflow.add_edge(
        "preprocess",
        "detect"
    )


    # DETECTION -> DATABASE
    workflow.add_edge(
        "detect",
        "database"
    )


    # DATABASE -> CONDITIONAL ROUTING
    workflow.add_conditional_edges(

        "database",

        route_after_database,

        {
            "rag": "rag",

            "finish": "finish"
        }
    )


    # RAG -> OPTIMIZED AI
    workflow.add_edge(
        "rag",
        "optimized_ai"
    )


    # OPTIMIZED AI -> SAVE ANALYSIS
    workflow.add_edge(
        "optimized_ai",
        "save_analysis"
    )


    # SAVE ANALYSIS -> FINISH
    workflow.add_edge(
        "save_analysis",
        "finish"
    )


    # FINISH -> END
    workflow.add_edge(
        "finish",
        END
    )


    # ========================================================
    # COMPILE GRAPH
    # ========================================================

    graph = workflow.compile()

    print(
        "\n[GRAPH] CyberShieldGPT workflow compiled successfully."
    )

    return graph


# ============================================================
# 3. CREATE GRAPH INSTANCE
# ============================================================

cybershield_graph = build_cybershield_graph()
