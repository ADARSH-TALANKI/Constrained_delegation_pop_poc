from policies.pap import POLICIES
from policies.pip import get_context


def evaluate_request(
        requested_permissions,
        purpose,
        context_name
):

    context = get_context(context_name)

    if not context:
        return False, "Context not found"

    for permission in requested_permissions:

        policy = POLICIES.get(permission)

        if not policy:
            return False, f"Permission not found in PAP: {permission}"

        # Purpose Validation

        if purpose not in policy["allowed_purposes"]:
            return False, f"Purpose validation failed for {permission}"

        # Delegation Depth Validation

        if context["delegation_depth"] > policy["max_delegation_depth"]:
            return False, f"Delegation depth exceeded for {permission}"

        # Context Validation

        required_context = policy["required_context"]

        for key, value in required_context.items():

            if context.get(key) != value:
                return False, (
                    f"Context requirement failed "
                    f"for {permission}: {key}"
                )

    return True, "Request Approved"


if __name__ == "__main__":

    result, reason = evaluate_request(
        requested_permissions=[
            "read_logs",
            "generate_incident_report"
        ],
        purpose="Incident Investigation",
        context_name="context_2"
    )

    print("\nRESULT :", result)
    print("REASON :", reason)