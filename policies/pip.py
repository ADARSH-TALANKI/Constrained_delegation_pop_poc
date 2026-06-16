# policies/pip.py

CONTEXTS = {

    "context_1": {
        "system_under_attack": False,
        "incident_exists": False,
        "incident_severity": "LOW",
        "delegation_depth": 0
    },

    "context_2": {
        "system_under_attack": False,
        "incident_exists": True,
        "incident_severity": "MEDIUM",
        "delegation_depth": 1
    },

    "context_3": {
        "system_under_attack": True,
        "incident_exists": True,
        "incident_severity": "HIGH",
        "delegation_depth": 1
    },

    "context_4": {
        "system_under_attack": True,
        "incident_exists": True,
        "incident_severity": "CRITICAL",
        "delegation_depth": 1
    },

    "context_5": {
        "system_under_attack": True,
        "incident_exists": True,
        "incident_severity": "CRITICAL",
        "delegation_depth": 2
    }
}


def get_context(context_name):

    return CONTEXTS.get(context_name)


if __name__ == "__main__":

    context = get_context("context_3")

    print(context)