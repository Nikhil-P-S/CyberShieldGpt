import json

from langchain_groq import ChatGroq
from src.optimized_ai import analyze_incident_optimized
from config import (
    GROQ_API_KEY,
    GROQ_MODEL
)
import json

from src.database import store_analysis

from src.preprocessing import preprocess_logs

from src.rules import run_security_rules

from src.ml_detection import detect_anomalies

from src.detection import combine_detection_results

from src.database import (
    create_database,
    store_logs,
    store_incident,
    store_analysis
)

from src.rag import (
    initialize_rag,
    retrieve_incident_knowledge
)


# ============================================================
# 1. GROQ LLM
# ============================================================

def get_llm():

    if not GROQ_API_KEY:

        raise ValueError(
            "GROQ_API_KEY is missing. "
            "Add it to your .env file."
        )

    return ChatGroq(
        api_key=GROQ_API_KEY,
        model=GROQ_MODEL,
        temperature=0.2
    )


def ask_groq(prompt):

    llm = get_llm()

    response = llm.invoke(prompt)

    content = response.content

    if isinstance(content, list):

        parts = []

        for item in content:

            if isinstance(item, dict):

                parts.append(
                    item.get("text", str(item))
                )

            else:

                parts.append(str(item))

        content = "\n".join(parts)

    return str(content).strip()


# ============================================================
# NODE 1 — PREPROCESSING AGENT
# ============================================================

def preprocess_node(state):

    print("\n[AGENT] Preprocessing Agent")

    file_path = state["file_path"]

    logs, behavioral_features = preprocess_logs(
        file_path
    )

    return {
        "logs": logs,
        "behavioral_features": behavioral_features,
        "status": "preprocessed"
    }


# ============================================================
# NODE 2 — RULE + ML DETECTION AGENT
# ============================================================

def detection_node(state):

    print("\n[AGENT] Security Detection Agent")

    logs = state["logs"]

    behavioral_features = state[
        "behavioral_features"
    ]

    # --------------------------------------------------------
    # RULE-BASED DETECTION
    # --------------------------------------------------------

    rule_results = run_security_rules(
        logs,
        behavioral_features
    )

    print(
        "[DETECTION] Rule findings:",
        len(rule_results)
    )

    # --------------------------------------------------------
    # MACHINE LEARNING DETECTION
    # --------------------------------------------------------

    ml_results = detect_anomalies(
        behavioral_features
    )

    ml_count = int(
        ml_results["ml_anomaly"].sum()
    )

    print(
        "[DETECTION] ML anomalies:",
        ml_count
    )

    # --------------------------------------------------------
    # COMBINE RULE + ML OUTPUTS
    # --------------------------------------------------------

    incidents = combine_detection_results(
        behavioral_features,
        rule_results,
        ml_results
    )

    print(
        "[DETECTION] Combined incidents:",
        len(incidents)
    )

    return {
        "rule_results": rule_results,
        "ml_results": ml_results,
        "incidents": incidents,
        "status": "detection_completed"
    }


# ============================================================
# NODE 3 — DATABASE AGENT
# ============================================================

def database_node(state):

    print("\n[AGENT] Database Agent")

    create_database()

    # Save all uploaded logs.
    stored_log_count = store_logs(
        state["logs"]
    )

    # Save detected incidents.
    stored_incident_ids = []

    for incident in state.get("incidents", []):

        incident_id = store_incident(
            incident
        )

        stored_incident_ids.append(
            incident_id
        )

    print(
        "[DATABASE] Logs:",
        stored_log_count
    )

    print(
        "[DATABASE] Incidents:",
        len(stored_incident_ids)
    )

    return {
        "stored_log_count": stored_log_count,
        "stored_incident_ids": stored_incident_ids,
        "status": "database_saved"
    }


# ============================================================
# NODE 4 — RAG KNOWLEDGE RETRIEVAL AGENT
# ============================================================

def rag_node(state):

    print("\n[AGENT] RAG Knowledge Retrieval Agent")

    initialize_rag()

    rag_results = []

    for incident in state.get("incidents", []):

        print(
            "[RAG] Retrieving knowledge for:",
            incident["ip_address"]
        )

        retrieved = retrieve_incident_knowledge(
            incident,
            k=3
        )

        sources = []

        for document in retrieved.get("results", []):

            metadata = document.metadata or {}

            sources.append({
                "source": metadata.get(
                    "source_file",
                    metadata.get("source", "Unknown")
                ),
                "content": document.page_content
            })

        rag_results.append({

            "ip_address": incident["ip_address"],

            "query": retrieved.get(
                "query",
                ""
            ),

            "context": retrieved.get(
                "context",
                ""
            ),

            "sources": sources
        })

    print(
        "[RAG] Knowledge retrieved for:",
        len(rag_results),
        "incidents"
    )

    return {
        "rag_results": rag_results,
        "status": "knowledge_retrieved"
    }


# ============================================================
# HELPER — ORGANIZE EVIDENCE BY IP
# ============================================================

def get_evidence_by_ip(state):

    analyses = {
        item["ip_address"]: item["analysis"]
        for item in state.get("log_analyses", [])
    }

    threats = {
        item["ip_address"]: item["threat_type"]
        for item in state.get("threat_classifications", [])
    }

    recommendations = {
        item["ip_address"]: item["recommendation"]
        for item in state.get("recommendations", [])
    }

    rag_results = {
        item["ip_address"]: item
        for item in state.get("rag_results", [])
    }

    rules_by_ip = {}

    for item in state.get("rule_results", []):

        ip = str(item["ip_address"])

        rules_by_ip.setdefault(
            ip,
            []
        ).append(item)

    ml_by_ip = {}

    ml_results = state.get("ml_results")

    if ml_results is not None:

        for _, row in ml_results.iterrows():

            ml_by_ip[str(row["ip_address"])] = (
                row.to_dict()
            )

    return (
        analyses,
        threats,
        recommendations,
        rag_results,
        rules_by_ip,
        ml_by_ip
    )


# ============================================================
# NODE 5 — LOG ANALYSIS AGENT
# ============================================================

def log_analysis_node(state):

    print("\n[AGENT] Groq Log Analysis Agent")

    rag_by_ip = {
        item["ip_address"]: item
        for item in state.get("rag_results", [])
    }

    log_analyses = []

    for incident in state.get("incidents", []):

        ip = str(incident["ip_address"])

        rag = rag_by_ip.get(ip, {})

        prompt = f"""
You are CyberShieldGPT's defensive cybersecurity
Log Analysis Agent.

Analyze the supplied security incident.

Do not invent users, timestamps, events, systems,
attacker identities, or evidence.

Clearly distinguish observed facts from hypotheses.

INCIDENT DATA:

{json.dumps(incident, indent=2, default=str)}

RAG RETRIEVED KNOWLEDGE:

{rag.get("context", "")}

Analyze:

1. Observed security events.
2. Suspicious behavioral patterns.
3. Possible security implications.
4. Supporting evidence.
5. Potential benign explanations.
6. Missing information.
7. Whether further investigation is required.

An unusual event is not automatically a confirmed attack.
"""

        analysis = ask_groq(prompt)

        log_analyses.append({

            "ip_address": ip,

            "analysis": analysis
        })

    return {
        "log_analyses": log_analyses,
        "status": "log_analysis_completed"
    }


# ============================================================
# NODE 6 — THREAT CLASSIFICATION AGENT
# ============================================================

def threat_classification_node(state):

    print("\n[AGENT] Groq Threat Classification Agent")

    analyses, _, _, rag_by_ip, rules_by_ip, ml_by_ip = (
        get_evidence_by_ip(state)
    )

    threat_classifications = []

    for incident in state.get("incidents", []):

        ip = str(incident["ip_address"])

        prompt = f"""
You are CyberShieldGPT's Threat Classification Agent.

Classify the likely cybersecurity threat based on
the supplied rule, ML, RAG, and log analysis evidence.

INCIDENT:

{json.dumps(incident, indent=2, default=str)}

RULE-BASED OUTPUT:

{json.dumps(rules_by_ip.get(ip, []), indent=2, default=str)}

ML OUTPUT:

{json.dumps(ml_by_ip.get(ip, {}), indent=2, default=str)}

RAG KNOWLEDGE:

{rag_by_ip.get(ip, {}).get("context", "")}

LOG ANALYSIS:

{analyses.get(ip, "")}

Possible categories:

- Brute-force login attempt
- Suspicious login
- Unauthorized access
- Credential stuffing
- Privilege escalation
- Unusual activity
- Insufficient evidence

Return:

Threat category:
Confidence: Low / Medium / High
Evidence:
Alternative explanations:
Reason for classification:
Further investigation required:

Do not claim a confirmed attack without sufficient evidence.
"""

        classification = ask_groq(prompt)

        threat_classifications.append({

            "ip_address": ip,

            "threat_type": classification
        })

    return {
        "threat_classifications": threat_classifications,
        "status": "classification_completed"
    }


# ============================================================
# NODE 7 — RECOMMENDATION AGENT
# ============================================================

def recommendation_node(state):

    print("\n[AGENT] Groq Recommendation Agent")

    (
        analyses,
        threats,
        _,
        rag_by_ip,
        rules_by_ip,
        ml_by_ip
    ) = get_evidence_by_ip(state)

    recommendations = []

    for incident in state.get("incidents", []):

        ip = str(incident["ip_address"])

        rag = rag_by_ip.get(ip, {})

        # All three main detection and knowledge outputs
        # are passed into the same LLM recommendation prompt.

        prompt = f"""
You are CyberShieldGPT's Defensive Recommendation Agent.

Your responsibility is to generate threat-specific
defensive recommendations.

Combine the following:

1. Rule-based detection.
2. ML anomaly prediction.
3. RAG-retrieved cybersecurity knowledge.
4. Log analysis.
5. Threat classification.

INCIDENT:

{json.dumps(incident, indent=2, default=str)}

RULE-BASED DETECTION:

{json.dumps(rules_by_ip.get(ip, []), indent=2, default=str)}

MACHINE LEARNING PREDICTION:

{json.dumps(ml_by_ip.get(ip, {}), indent=2, default=str)}

RAG RETRIEVED KNOWLEDGE:

{rag.get("context", "")}

LOG ANALYSIS:

{analyses.get(ip, "")}

THREAT CLASSIFICATION:

{threats.get(ip, "")}

Generate:

1. Combined threat assessment.
2. Explanation of rule-based findings.
3. Explanation of ML anomaly prediction.
4. Relevant RAG knowledge.
5. Immediate investigation steps.
6. Recommended defensive actions.
7. Evidence that should be preserved.
8. Human approval or escalation requirements.
9. Post-remediation verification.

IMPORTANT:

- ML anomalies are not proof of an attack.
- Consider false positives.
- Consider shared NAT and legitimate users.
- Do not claim that actions have already been executed.
- Require authorized human approval for disruptive actions.
"""

        recommendation = ask_groq(prompt)

        recommendations.append({

            "ip_address": ip,

            "recommendation": recommendation
        })

    return {
        "recommendations": recommendations,
        "status": "recommendations_completed"
    }


# ============================================================
# NODE 8 — FINAL INCIDENT REPORT AGENT
# ============================================================

def report_generation_node(state):

    print("\n[AGENT] Groq Final Incident Report Agent")

    (
        analyses,
        threats,
        recommendations,
        rag_by_ip,
        rules_by_ip,
        ml_by_ip
    ) = get_evidence_by_ip(state)

    reports = []

    for incident in state.get("incidents", []):

        ip = str(incident["ip_address"])

        rag = rag_by_ip.get(ip, {})

        prompt = f"""
You are CyberShieldGPT's Final Incident Report Agent.

Generate a complete professional cybersecurity
incident report using ALL available information.

INCIDENT INFORMATION:

{json.dumps(incident, indent=2, default=str)}

RULE-BASED DETECTION:

{json.dumps(rules_by_ip.get(ip, []), indent=2, default=str)}

ML THREAT PREDICTION:

{json.dumps(ml_by_ip.get(ip, {}), indent=2, default=str)}

RAG RETRIEVED KNOWLEDGE:

{rag.get("context", "")}

RAG SOURCES:

{json.dumps(rag.get("sources", []), indent=2, default=str)}

LOG ANALYSIS:

{analyses.get(ip, "")}

THREAT CLASSIFICATION:

{threats.get(ip, "")}

RECOMMENDATIONS:

{recommendations.get(ip, "")}

Create these report sections:

1. Executive Summary
2. Incident Overview
3. Affected IP Address
4. Rule-Based Detection Findings
5. ML Anomaly Prediction
6. RAG Knowledge Applied
7. Threat Classification
8. Evidence and Observed Patterns
9. Severity and Security Score
10. Recommended Defensive Actions
11. Human Approval and Escalation
12. False-Positive Considerations
13. Final Assessment

RULES:

- Do not invent evidence.
- Separate facts from hypotheses.
- Explain ML limitations.
- Treat RAG as guidance, not proof.
- Do not claim remediation was performed.
- Explain why the recommended actions are appropriate.
"""

        report = ask_groq(prompt)

        reports.append({

            "ip_address": ip,

            "report": report
        })

    return {
        "reports": reports,
        "status": "reports_generated"
    }


# ============================================================
# NODE 9 — SAVE ANALYSIS TO SQLITE
# ============================================================

# ============================================================
# SAVE OPTIMIZED AI ANALYSIS
# ============================================================



def save_analysis_node(state):

    print("\n[AGENT] Saving AI analysis")

    combined_results = state.get(
        "combined_ai_results",
        []
    )

    incidents = state.get(
        "incidents",
        []
    )

    saved_count = 0

    for result in combined_results:

        ip_address = str(
            result.get("ip_address", "")
        )

        # Find the matching incident.
        matching_incident = next(
            (
                incident
                for incident in incidents
                if str(
                    incident.get("ip_address", "")
                ) == ip_address
            ),
            None
        )

        if matching_incident is None:

            print(
                "[AGENT] Incident not found:",
                ip_address
            )

            continue

        # Get the actual database primary key.
        incident_id = (
            matching_incident.get("incident_id")
            or matching_incident.get("id")
        )

        if incident_id is None:

            print(
                "[AGENT] Missing database ID:",
                ip_address
            )

            continue

        # Extract AI-generated fields.
        threat_type = result.get(
            "threat_type",
            "Unclassified"
        )

        explanation = result.get(
            "analysis",
            ""
        )

        historical_context = result.get(
            "historical_context",
            ""
        )

        recommendation = result.get(
            "recommendations",
            []
        )

        report = result.get(
            "final_report",
            ""
        )

        # Convert recommendations BEFORE calling database.
        if isinstance(recommendation, (list, dict)):

            recommendation = json.dumps(
                recommendation,
                ensure_ascii=False,
                indent=2,
                default=str
            )

        if isinstance(historical_context, (list, dict)):

            historical_context = json.dumps(
                historical_context,
                ensure_ascii=False,
                indent=2,
                default=str
            )

        print(
            f"\n[AGENT] Saving incident: {incident_id}"
        )

        print(
            "[AGENT] Recommendation type:",
            type(recommendation).__name__
        )

        # Save to SQLite.
        store_analysis(
            incident_id=incident_id,
            threat_type=threat_type,
            explanation=explanation,
            historical_context=historical_context,
            recommendation=recommendation,
            report=report
        )

        saved_count += 1

    print(
        f"\n[AGENT] Successfully saved {saved_count} AI analyses."
    )

    return state


# ============================================================
# OPTIMIZED AI NODE
# ============================================================

def optimized_ai_node(state):

    print("\n[CYBERSHIELDGPT] Optimized AI analysis started")

    incidents = state.get("incidents", [])

    rule_results = state.get("rule_results", [])

    ml_results = state.get("ml_results")

    rag_results = state.get("rag_results", [])

    combined_results = []

    for incident in incidents:

        ip = str(incident.get("ip_address"))

        print(f"\n[AI] Processing incident: {ip}")

        # ----------------------------------------
        # Get rules for this incident
        # ----------------------------------------

        incident_rules = [
            rule
            for rule in rule_results
            if str(rule.get("ip_address")) == ip
        ]

        # ----------------------------------------
        # Get ML findings
        # ----------------------------------------

        ml_details = {}

        if ml_results is not None and not ml_results.empty:

            matching_ml = ml_results[
                ml_results["ip_address"].astype(str) == ip
            ]

            if not matching_ml.empty:

                ml_details = matching_ml.iloc[0].to_dict()

        # ----------------------------------------
        # Get relevant RAG context
        # ----------------------------------------

        rag_context = ""

        for item in rag_results:

            if str(item.get("ip_address")) == ip:

                rag_context = item.get(
                    "context", ""
                )

                break

        # ----------------------------------------
        # ONE COMBINED GROQ CALL
        # ----------------------------------------

        ai_result = analyze_incident_optimized(

            incident=incident,

            rule_results=incident_rules,

            ml_details=ml_details,

            rag_context=rag_context,

            log_sample=[]
        )

        # ----------------------------------------
        # Store structured result in state
        # ----------------------------------------

        combined_results.append({

            "ip_address": ip,

            "analysis": ai_result.get(
                "analysis", ""
            ),

            "threat_type": ai_result.get(
                "threat_type", "Unconfirmed"
            ),

            "confidence": ai_result.get(
                "confidence", ""
            ),

            "recommendations": ai_result.get(
                "recommendations", []
            ),

            "final_report": ai_result.get(
                "final_report", ""
            ),

            "optimization": ai_result.get(
                "_optimization", {}
            )
        })

    state["combined_ai_results"] = combined_results

    # Maintain compatibility with the previous output fields.

    state["log_analyses"] = [
        {
            "ip_address": item["ip_address"],
            "analysis": item["analysis"]
        }
        for item in combined_results
    ]

    state["threat_classifications"] = [
        {
            "ip_address": item["ip_address"],
            "threat_type": item["threat_type"],
            "confidence": item["confidence"]
        }
        for item in combined_results
    ]

    state["recommendations"] = [
        {
            "ip_address": item["ip_address"],
            "recommendation": item["recommendations"]
        }
        for item in combined_results
    ]

    state["reports"] = [
        {
            "ip_address": item["ip_address"],
            "report": item["final_report"]
        }
        for item in combined_results
    ]

    print("\n[CYBERSHIELDGPT] Optimized AI analysis completed")

    return state

# ============================================================
# NODE 10 — FINISH
# ============================================================

def finish_node(state):

    print("\n======================================")
    print("CYBERSHIELDGPT WORKFLOW COMPLETED")
    print("======================================")

    return {
        "status": "completed"
    }