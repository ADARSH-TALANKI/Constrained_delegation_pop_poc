from policies.pdp import evaluate_request
from agents.subagent import SubAgent
from credentials.issuer import IssuerAuthority


def validate_delegation(
        parent_permissions,
        requested_permissions,
        purpose,
        context_name
):

    # Constraint 1:
    # Requested permissions must be subset of parent permissions

    for permission in requested_permissions:

        if permission not in parent_permissions:

            return (
                False,
                f"Parent does not possess: {permission}"
            )

    # Constraint 2:
    # PAP + PIP + PDP validation

    result, reason = evaluate_request(
        requested_permissions,
        purpose,
        context_name
    )

    if not result:

        return False, reason

    return True, "Delegation Approved"


def perform_delegation(
        parent_permissions,
        requested_permissions,
        purpose,
        context_name,
        subagent,
        issuer
):

    approved, reason = validate_delegation(
        parent_permissions,
        requested_permissions,
        purpose,
        context_name
    )

    if not approved:

        return False, reason

    delegated_vc = issuer.issue_delegated_vc(
        subagent_did=subagent.did,
        permissions=requested_permissions,
        purpose=purpose,
        delegation_depth=1
    )

    subagent.vc = delegated_vc

    subagent.permissions = delegated_vc["permissions"]

    return True, "Delegated VC Issued"


if __name__ == "__main__":

    issuer = IssuerAuthority()

    subagent = SubAgent()

    parent_permissions = [
        "read_logs",
        "generate_incident_report",
        "quarantine_endpoint"
    ]

    requested_permissions = [
        "read_logs",
        "generate_incident_report"
    ]

    result, reason = perform_delegation(
        parent_permissions=parent_permissions,
        requested_permissions=requested_permissions,
        purpose="Incident Investigation",
        context_name="context_2",
        subagent=subagent,
        issuer=issuer
    )

    print("\nRESULT :", result)
    print("REASON :", reason)

    print("\n=== SUBAGENT VC ===")
    print(subagent.vc)

    print("\n=== SUBAGENT PERMISSIONS ===")
    print(subagent.permissions)