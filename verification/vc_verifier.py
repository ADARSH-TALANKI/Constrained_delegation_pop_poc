import json

from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError


def verify_vc(vc, issuer_public_key):

    signature = vc["signature"]

    vc_copy = vc.copy()

    vc_copy.pop("signature")

    message = json.dumps(
        vc_copy,
        sort_keys=True
    ).encode()

    verify_key = VerifyKey(
        issuer_public_key,
        encoder=HexEncoder
    )

    try:

        verify_key.verify(
            message,
            bytes.fromhex(signature)
        )

        return True

    except BadSignatureError:

        return False
    

if __name__ == "__main__":

 from credentials.issuer import IssuerAuthority
issuer = IssuerAuthority()
vc = issuer.issue_parent_vc(
    "did:agent:test123"
)
print("\n===== ORIGINAL VC =====")

result = verify_vc(
    vc,
    issuer.public_key
)
print("VC VALID:", result)

# ATTACK

vc["permissions"].append(
    "block_ip"
)

print("\n===== TAMPERED VC =====")

result = verify_vc(
    vc,
    issuer.public_key
)

print("VC VALID:", result)