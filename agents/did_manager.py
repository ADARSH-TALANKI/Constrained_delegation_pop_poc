# Goal
# Generate a DID from the public key.
# For MVP:
# we are NOT implementing a full DID method.
# Instead:
# did:agent:<first few chars of public key>
# Example:
# did:agent:a7f92c31

from crypto_utils.key_manager import generate_keypair
def generate_did(public_key):
    return f"did:agent:{public_key[:8]}"


if __name__ == "__main__":
    keys = generate_keypair()

    did = generate_did(keys["public_key"])

    print("\n=== AGENT IDENTITY ===")
    print(f"Public Key : {keys['public_key']}")
    print(f"DID        : {did}")


def create_agent_identity():

    keys = generate_keypair()

    return {
        "did": generate_did(keys["public_key"]),
        "public_key": keys["public_key"],
        "private_key": keys["private_key"]
    }