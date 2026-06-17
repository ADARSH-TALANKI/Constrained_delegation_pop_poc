import uuid
import json

from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

from crypto_utils.signature_manager import sign_data

# Challenge Generator
def generate_challenge():
    return {
        "challenge": str(uuid.uuid4())
    }

# Create PoP Proof
def create_pop_proof(
        challenge,
        private_key
):
    signature = sign_data(
        challenge,
        private_key
    )
    return signature

# Verify PoP
def verify_pop(
        challenge,
        signature,
        public_key
):
    message = json.dumps(
        challenge,
        sort_keys=True
    ).encode()

    verify_key = VerifyKey(
        public_key,
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

    from agents.subagent import SubAgent
    subagent = SubAgent()
    challenge = generate_challenge()

    print("\nCHALLENGE")
    print(challenge)

    signature = create_pop_proof(
        challenge,
        subagent.private_key
    )

    print("\nSIGNATURE")
    print(signature)

    # result = verify_pop(
    #     challenge,
    #     signature,
    #     subagent.public_key
    # )
    from agents.subagent import SubAgent

    fake_agent = SubAgent()

    result = verify_pop(
        challenge,
        signature,
        fake_agent.public_key
    )

    print("\nPOP RESULT")
    print(result)