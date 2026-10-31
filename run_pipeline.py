
from src.graph import build_cybershield_graph


def main():
    print("\n" + "=" * 60)
    print("CYBERSHIELD GPT — STARTED")
    print("=" * 60)

    graph = build_cybershield_graph()

    initial_state = {
        "file_path": "data/security_logs.csv",
        "status": "started",
        "error": "",
    }

    result = graph.invoke(initial_state)

    print("\n" + "=" * 60)
    print("CYBERSHIELD GPT — PIPELINE SUMMARY")
    print("=" * 60)

    print("Status:", result.get("status"))
    print("Processed logs:", len(result.get("logs", [])))
    print("Rule findings:", len(result.get("rule_results", [])))
    print("Suspicious incidents:", len(result.get("incidents", [])))
    print("Logs saved:", result.get("stored_log_count", 0))
    print("Incidents saved:", len(result.get("stored_incident_ids", [])))
    print("Analysis records saved:", result.get("saved_analysis_count", 0))

    for incident in result.get("incidents", []):
        ip = incident["ip_address"]

        print("\n" + "-" * 60)
        print("INCIDENT:", ip)
        print("Severity:", incident["severity"])
        print("Security score:", incident["security_score"])
        print("Triggered rules:", incident["triggered_rules"])
        print("ML anomaly:", incident["ml_anomaly"])

        for item in result.get("log_analyses", []):
            if item["ip_address"] == ip:
                print("\nLOG ANALYSIS")
                print(item["analysis"])

        for item in result.get("threat_classifications", []):
            if item["ip_address"] == ip:
                print("\nTHREAT CLASSIFICATION")
                print(item["threat_type"])

        for item in result.get("recommendations", []):
            if item["ip_address"] == ip:
                print("\nRECOMMENDATIONS")
                print(item["recommendation"])

        for item in result.get("reports", []):
            if item["ip_address"] == ip:
                print("\nINCIDENT REPORT")
                print(item["report"])

    print("\n" + "=" * 60)
    print("CYBERSHIELD GPT — FINISHED")
    print("=" * 60)


if __name__ == "__main__":
    main()
