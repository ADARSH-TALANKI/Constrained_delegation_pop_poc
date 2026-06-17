REVOKED_VCS = set()


def revoke_vc(vc_id):

    REVOKED_VCS.add(vc_id)

    return True


def is_revoked(vc_id):

    return vc_id in REVOKED_VCS


if __name__ == "__main__":

    sample_vc_id = "vc123"

    print(
        "Before Revocation:",
        is_revoked(sample_vc_id)
    )

    revoke_vc(sample_vc_id)

    print(
        "After Revocation:",
        is_revoked(sample_vc_id)
    )