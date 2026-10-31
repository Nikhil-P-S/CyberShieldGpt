# ============================================================
# CHECK SQLITE INCIDENTS
# ============================================================

from src.database import get_all_incidents


rows = get_all_incidents()


print(
    f"Total incidents in database: {len(rows)}"
)


for row in rows:

    print(
        "\n--------------------------------"
    )

    print(
        f"Incident ID: {row['id']}"
    )

    print(
        f"IP: {row['ip_address']}"
    )

    print(
        f"Severity: {row['severity']}"
    )

    print(
        f"Security Score: {row['security_score']}"
    )

    print(
        f"Rules: {row['triggered_rules']}"
    )

    print(
        f"ML Anomaly: {row['ml_anomaly']}"
    )