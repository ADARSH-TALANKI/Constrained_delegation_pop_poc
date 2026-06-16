import uuid
from datetime import datetime, timedelta


def create_vc(
        issuer,
        subject,
        permissions,
        purpose,
        delegation_depth,
        expiry_minutes=30):

    vc = {
        "vc_id": str(uuid.uuid4()),
        "issuer": issuer,
        "subject": subject,
        "permissions": permissions,
        "purpose": purpose,
        "issued_at": datetime.utcnow().isoformat(),
        "expiry": (
            datetime.utcnow() +
            timedelta(minutes=expiry_minutes)
        ).isoformat(),
        "delegation_depth": delegation_depth,
        "signature": "PENDING"
    }

    return vc


if __name__ == "__main__":

    vc = create_vc(
        issuer="did:issuer:soc_authority",

        subject="did:agent:test123",

        permissions=[
            "read_alerts",
            "read_logs",
            "read_metrics",
            "generate_incident_report",
            "quarantine_endpoint"
        ],

        purpose="Incident Investigation",

        delegation_depth=2
    )

    print(vc)