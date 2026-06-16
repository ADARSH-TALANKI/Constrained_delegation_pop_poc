from credentials.vc_manager import create_vc
from crypto_utils.key_manager import generate_keypair
from crypto_utils.signature_manager import sign_data


class IssuerAuthority:

    def __init__(self):
        # Issuer Identity
        self.did = "did:issuer:soc_authority"

        # Issuer Key Pair
        keys = generate_keypair()

        self.private_key = keys["private_key"]
        self.public_key = keys["public_key"]

    def issue_parent_vc(self, subject_did):

        permissions = [
            "read_alerts",
            "read_logs",
            "read_metrics",
            "generate_incident_report",
            "quarantine_endpoint"
        ]

        vc = create_vc(
            issuer=self.did,
            subject=subject_did,
            permissions=permissions,
            purpose="SOC Operations",
            delegation_depth=2
        )

        vc_to_sign = vc.copy()
        vc_to_sign.pop("signature")
        signature = sign_data(
            vc_to_sign,
            self.private_key
        )
        vc["signature"] = signature
        
        return vc

    def display_info(self):

        print("\n=== ISSUER AUTHORITY ===")
        print(f"DID         : {self.did}")
        print(f"Public Key  : {self.public_key}")

    def issue_delegated_vc(
        self,
        subagent_did,
        permissions,
        purpose,
        delegation_depth
):

        vc = create_vc(
            issuer=self.did,
            subject=subagent_did,
            permissions=permissions,
            purpose=purpose,
            delegation_depth=delegation_depth
        )

        vc_to_sign = vc.copy()

        vc_to_sign.pop("signature")

        signature = sign_data(
            vc_to_sign,
            self.private_key
        )

        vc["signature"] = signature

        return vc


if __name__ == "__main__":

    issuer = IssuerAuthority()

    issuer.display_info()

    vc = issuer.issue_parent_vc(
        "did:agent:test123"
    )

    print("\n=== ISSUED VC ===")
    print(vc)