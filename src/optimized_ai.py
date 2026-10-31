
# src/optimized_ai.py

import os
import re
import json
import time
import hashlib
from functools import lru_cache

from groq import RateLimitError
from langchain_groq import ChatGroq


# ============================================================
# CONFIGURATION
# ============================================================

MAX_RAG_CHARS = 2200
MAX_RULES = 5
MAX_LOG_ROWS = 5
MAX_PROMPT_CHARS = 8500
MAX_OUTPUT_TOKENS = 900
MAX_RETRIES = 3


# ============================================================
# 1. INITIALIZE GROQ
# ============================================================

def get_optimized_llm():

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise ValueError("GROQ_API_KEY is missing.")

    return ChatGroq(
        model=os.getenv(
            "GROQ_MODEL",
            "openai/gpt-oss-120b"
        ),
        api_key=api_key,
        temperature=0.1,
        max_tokens=MAX_OUTPUT_TOKENS,
        timeout=60,
        max_retries=0
    )


# ============================================================
# 2. CLEAN TEXT
# ============================================================

def clean_text(value, limit=400):

    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        value = json.dumps(
            value,
            default=str
        )

    value = re.sub(
        r"\s+",
        " ",
        str(value)
    ).strip()

    return value[:limit]


# ============================================================
# 3. CONTEXTUAL COMPRESSION
# ============================================================

def get_keywords(text):

    stop_words = {
        "the", "and", "for", "with",
        "from", "this", "that", "were",
        "was", "are", "has", "have",
        "into", "then", "not", "but"
    }

    words = re.findall(
        r"[a-zA-Z0-9_-]{3,}",
        str(text).lower()
    )

    return {
        word for word in words
        if word not in stop_words
    }


def compress_rag_context(
    rag_context,
    incident,
    max_chars=MAX_RAG_CHARS
):

    if not rag_context:
        return "No relevant knowledge retrieved."

    incident_text = json.dumps(
        incident,
        default=str
    )

    query_words = get_keywords(incident_text)

    sentences = re.split(
        r"(?<=[.!?])\s+|\n+",
        str(rag_context)
    )

    ranked_sentences = []

    for index, sentence in enumerate(sentences):

        sentence = sentence.strip()

        if len(sentence) < 20:
            continue

        sentence_words = get_keywords(sentence)

        relevance = len(
            query_words.intersection(sentence_words)
        )

        security_bonus = 0

        security_terms = [
            "brute force",
            "failed login",
            "unauthorized",
            "privilege escalation",
            "malware",
            "credential",
            "access denied",
            "incident response",
            "containment",
            "multi-factor"
        ]

        for term in security_terms:

            if term in sentence.lower():
                security_bonus += 1

        score = relevance + security_bonus

        ranked_sentences.append(
            (score, index, sentence)
        )

    ranked_sentences.sort(
        key=lambda item: (
            item[0],
            -item[1]
        ),
        reverse=True
    )

    selected = []
    total_chars = 0

    for score, index, sentence in ranked_sentences:

        if score == 0:
            continue

        if total_chars + len(sentence) > max_chars:
            continue

        selected.append(
            (index, sentence)
        )

        total_chars += len(sentence)

    selected.sort(
        key=lambda item: item[0]
    )

    result = "\n".join(
        sentence
        for index, sentence in selected
    )

    return result or str(rag_context)[:max_chars]


# ============================================================
# 4. COMPRESS INCIDENT EVIDENCE
# ============================================================

def compress_incident_evidence(
    incident,
    rule_results,
    ml_details,
    rag_context,
    log_sample=None
):

    compact_rules = []

    for rule in (rule_results or [])[:MAX_RULES]:

        compact_rules.append({

            "rule": clean_text(
                rule.get("rule"),
                100
            ),

            "severity": clean_text(
                rule.get("severity"),
                30
            ),

            "reason": clean_text(
                rule.get("reason"),
                180
            )
        })

    ml_fields = [
        "ml_anomaly",
        "ml_prediction",
        "anomaly_score",
        "Failed_Login_Count",
        "Login_Frequency",
        "Access_Count",
        "Unique_User_Count",
        "Night_Login_Count",
        "Access_Denied_Count"
    ]

    compact_ml = {}

    if isinstance(ml_details, dict):

        for field in ml_fields:

            if field in ml_details:

                compact_ml[field] = ml_details[field]

    compact_incident = {

        "ip_address": incident.get(
            "ip_address"
        ),

        "severity": incident.get(
            "severity"
        ),

        "security_score": incident.get(
            "security_score"
        ),

        "triggered_rules": clean_text(
            incident.get("triggered_rules"),
            250
        ),

        "failed_login_count": incident.get(
            "failed_login_count"
        ),

        "login_frequency": incident.get(
            "login_frequency"
        ),

        "access_count": incident.get(
            "access_count"
        ),

        "unique_user_count": incident.get(
            "unique_user_count"
        ),

        "night_login_count": incident.get(
            "night_login_count"
        ),

        "access_denied_count": incident.get(
            "access_denied_count"
        )
    }

    compact_logs = []

    for row in (log_sample or [])[:MAX_LOG_ROWS]:

        if isinstance(row, dict):

            compact_logs.append({

                "timestamp": clean_text(
                    row.get("timestamp"), 35
                ),

                "user": clean_text(
                    row.get("user"), 40
                ),

                "ip_address": clean_text(
                    row.get("ip_address"), 50
                ),

                "event_type": clean_text(
                    row.get("event_type"), 50
                ),

                "status": clean_text(
                    row.get("status"), 30
                ),

                "resource": clean_text(
                    row.get("resource"), 50
                )
            })

    compressed_rag = compress_rag_context(
        rag_context,
        compact_incident
    )

    return {

        "incident": compact_incident,

        "rule_findings": compact_rules,

        "ml_findings": compact_ml,

        "rag_knowledge": compressed_rag,

        "representative_logs": compact_logs
    }


# ============================================================
# 5. BUILD ONE COMPACT PROMPT
# ============================================================

def build_incident_prompt(evidence):

    evidence_json = json.dumps(
        evidence,
        ensure_ascii=False,
        default=str
    )

    prompt = f"""
You are CyberShieldGPT, a defensive cybersecurity analyst.

Analyze the supplied incident evidence.

Return ONLY valid JSON using this structure:

{{
  "analysis": "Detailed evidence-based explanation",
  "threat_type": "Threat classification",
  "confidence": "Low, Medium or High with reason",
  "recommendations": [
    {{
      "priority": "P1/P2/P3",
      "action": "Recommended defensive action",
      "reason": "Why this action is needed",
      "verification": "How to verify completion"
    }}
  ],
  "final_report": "Executive-ready incident report"
}}

IMPORTANT RULES:

1. Use only supplied evidence.
2. Separate confirmed observations from hypotheses.
3. An ML anomaly is not proof of an attack.
4. Do not invent IP reputation or events.
5. Provide a maximum of five recommendations.
6. Prioritize recommendations by security impact.
7. Mention uncertainty and missing evidence.
8. Do not repeat the complete input.
9. Do not claim that an action has been executed.
10. Recommendations must be defensive.

INCIDENT EVIDENCE:

{evidence_json}
"""

    # Hard prompt-size safeguard.
    return prompt[:MAX_PROMPT_CHARS]


# ============================================================
# 6. GROQ RATE-LIMIT RETRY
# ============================================================

def get_retry_delay(error, attempt):

    message = str(error)

    match = re.search(
        r"try again in ([0-9.]+)s",
        message,
        re.IGNORECASE
    )

    if match:

        server_wait = float(
            match.group(1)
        )

        return server_wait + 1.0

    # Fallback exponential backoff.
    return min(
        30,
        7 * (2 ** attempt)
    )


def call_groq_with_retry(prompt):

    llm = get_optimized_llm()

    for attempt in range(MAX_RETRIES + 1):

        try:

            print(
                f"[GROQ] Request attempt {attempt + 1}"
            )

            response = llm.invoke(prompt)

            content = response.content

            if isinstance(content, list):

                content = "\n".join(
                    str(item.get("text", item))
                    if isinstance(item, dict)
                    else str(item)
                    for item in content
                )

            return str(content)

        except RateLimitError as error:

            if attempt >= MAX_RETRIES:
                raise

            wait_time = get_retry_delay(
                error,
                attempt
            )

            print(
                f"[GROQ] TPM rate limit reached."
            )

            print(
                f"[GROQ] Waiting {wait_time:.1f} seconds."
            )

            time.sleep(wait_time)

        except Exception:
            raise

    raise RuntimeError(
        "Groq request failed after retries."
    )


# ============================================================
# 7. PARSE STRUCTURED AI OUTPUT
# ============================================================

def parse_ai_response(response_text):

    cleaned = response_text.strip()

    cleaned = re.sub(
        r"^```(?:json)?\s*|\s*```$",
        "",
        cleaned,
        flags=re.IGNORECASE
    )

    try:

        result = json.loads(cleaned)

        if isinstance(result, dict):
            return result

    except json.JSONDecodeError:
        pass

    match = re.search(
        r"\{.*\}",
        cleaned,
        flags=re.DOTALL
    )

    if match:

        try:

            result = json.loads(
                match.group(0)
            )

            if isinstance(result, dict):
                return result

        except json.JSONDecodeError:
            pass

    return {
        "analysis": cleaned,
        "threat_type": "Needs analyst validation",
        "confidence": "Low - invalid structured response",
        "recommendations": [],
        "final_report": cleaned
    }


# ============================================================
# 8. COMBINED INCIDENT ANALYSIS
# ============================================================

def analyze_incident_optimized(
    incident,
    rule_results,
    ml_details,
    rag_context,
    log_sample=None
):

    evidence = compress_incident_evidence(

        incident=incident,

        rule_results=rule_results,

        ml_details=ml_details,

        rag_context=rag_context,

        log_sample=log_sample
    )

    prompt = build_incident_prompt(
        evidence
    )

    print(
        "[OPTIMIZATION] Original dataset is NOT sent to Groq."
    )

    print(
        "[OPTIMIZATION] Compact prompt characters:",
        len(prompt)
    )

    response = call_groq_with_retry(
        prompt
    )

    result = parse_ai_response(
        response
    )

    result["_optimization"] = {

        "prompt_characters": len(prompt),

        "rag_context_characters": len(
            evidence["rag_knowledge"]
        ),

        "combined_ai_calls": 1,

        "compression": "Local contextual compression"
    }

    return result
