# print("I AM THE FILE BEING EXECUTED")
from policies.pdp import evaluate_request
from agents.subagent import SubAgent
from credentials.issuer import IssuerAuthority
from verification.vc_verifier import verify_vc
from resource_server.resource_server import request_access
from revocation.revocation_registry import (
    revoke_vc
)


def validate_delegation(
        parent_vc,
        requested_permissions,
        purpose,
        context_name,
        issuer
):

    # Step 1: Verify Parent VC

    if not verify_vc(
            parent_vc,
            issuer.public_key
    ):

        return False, "Parent VC verification failed"

    # Step 2: Extract permissions from Parent VC

    parent_permissions = parent_vc["permissions"]

    # Step 3: Subset validation

    for permission in requested_permissions:

        if permission not in parent_permissions:

            return (
                False,
                f"Parent does not possess: {permission}"
            )

    # Step 4: PDP Validation

    result, reason = evaluate_request(
        requested_permissions,
        purpose,
        context_name
    )

    if not result:

        return False, reason

    return True, "Delegation Approved"


def perform_delegation(
        parent_vc,
        requested_permissions,
        purpose,
        context_name,
        subagent,
        issuer
):

    approved, reason = validate_delegation(
        parent_vc,
        requested_permissions,
        purpose,
        context_name,
        issuer
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

    # Parent VC

    parent_vc = issuer.issue_parent_vc(
        "did:agent:parent123"
    )

    # SubAgent

    subagent = SubAgent()

    requested_permissions = [
        "read_logs",
        "generate_incident_report"
    ]

    # Delegation

    result, reason = perform_delegation(
        parent_vc=parent_vc,
        requested_permissions=requested_permissions,
        purpose="Incident Investigation",
        context_name="context_2",
        subagent=subagent,
        issuer=issuer
    )

    print("\n===== DELEGATION RESULT =====")

    print("RESULT :", result)
    print("REASON :", reason)

    if result:

        print("\n=== SUBAGENT VC ===")

        print(subagent.vc)

        print("\n=== SUBAGENT PERMISSIONS ===")

        print(subagent.permissions)

        # ----------------------------
        # TEST 1 : NORMAL ACCESS
        # ----------------------------

        access_result, access_reason = request_access(
            subagent,
            "read_logs",
            issuer.public_key
        )

        print("\n===== NORMAL ACCESS TEST =====")

        print(
            "RESULT :",
            access_result
        )

        print(
            "REASON :",
            access_reason
        )

        # ----------------------------
        # TEST 2 : REVOKE VC
        # ----------------------------

        print("\n===== REVOKING VC =====")

        revoke_vc(
            subagent.vc["vc_id"]
        )

        print(
            "Revoked VC ID :",
            subagent.vc["vc_id"]
        )

        # ----------------------------
        # TEST 3 : ACCESS AFTER REVOCATION
        # ----------------------------

        access_result, access_reason = request_access(
            subagent,
            "read_logs",
            issuer.public_key
        )

        print(
            "\n===== ACCESS AFTER REVOCATION ====="
        )

        print(
            "RESULT :",
            access_result
        )

        print(
            "REASON :",
            access_reason
        )