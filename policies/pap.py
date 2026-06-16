POLICIES = {

    "read_logs": {
        "tier": 1,
        "risk": "LOW",
        "allowed_purposes": [
            "SOC Operations",
            "Incident Investigation"
        ],
        "required_context": {},
        "max_delegation_depth": 2
    },

    "generate_incident_report": {
        "tier": 2,
        "risk": "MEDIUM",
        "allowed_purposes": [
            "Incident Investigation"
        ],
        "required_context": {
            "incident_exists": True
        },
        "max_delegation_depth": 2
    },

    "quarantine_endpoint": {
        "tier": 3,
        "risk": "HIGH",
        "allowed_purposes": [
            "Threat Containment"
        ],
        "required_context": {
            "system_under_attack": True,
            "incident_severity": "HIGH"
        },
        "max_delegation_depth": 1
    },

    "block_ip": {
        "tier": 3,
        "risk": "HIGH",
        "allowed_purposes": [
            "Threat Containment"
        ],
        "required_context": {
            "system_under_attack": True,
            "incident_severity": "CRITICAL"
        },
        "max_delegation_depth": 1
    }
}