from verification.vc_verifier import verify_vc

from proof_of_possesion.pop_manager import (
    generate_challenge,
    create_pop_proof,
    verify_pop
)

from revocation.revocation_registry import (
    is_revoked
)


def request_access(
        subagent,
        requested_permission,
        issuer_public_key
):

    print("\n===== RESOURCE REQUEST =====")

    # STEP 0
    # Check Revocation Status

    if is_revoked(
            subagent.vc["vc_id"]
    ):

        return False, "VC Revoked"

    print("Revocation Check : SUCCESS")

    # STEP 1
    # Verify VC

    if not verify_vc(
            subagent.vc,
            issuer_public_key
    ):

        return False, "VC Verification Failed"

    print("VC Verification : SUCCESS")

    # STEP 2
    # Verify Permission

    if requested_permission not in subagent.vc["permissions"]:

        return (
            False,
            "Permission Not Present In VC"
        )

    print("Permission Check : SUCCESS")

    # STEP 3
    # Generate Challenge

    challenge = generate_challenge()

    print("Challenge Generated")

    # STEP 4
    # Agent Creates PoP

    signature = create_pop_proof(
        challenge,
        subagent.private_key
    )

    print("PoP Generated")

    # STEP 5
    # Verify PoP

    if not verify_pop(
            challenge,
            signature,
            subagent.public_key
    ):

        return False, "PoP Verification Failed"

    print("PoP Verification : SUCCESS")

    return True, "Access Granted"


if __name__ == "__main__":

    from credentials.issuer import IssuerAuthority

    issuer = IssuerAuthority()

    print(
        "\nResource Server Ready"
    )