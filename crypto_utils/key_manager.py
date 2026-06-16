from nacl.signing import SigningKey
from nacl.encoding import HexEncoder


def generate_keypair():
    private_key = SigningKey.generate()
    public_key = private_key.verify_key

    return {
        "private_key": private_key.encode(encoder=HexEncoder).decode(),
        "public_key": public_key.encode(encoder=HexEncoder).decode()
    }


if __name__ == "__main__":
    keys = generate_keypair()

    print("\n=== GENERATED KEY PAIR ===")
    print(f"Private Key: {keys['private_key']}")
    print(f"Public Key : {keys['public_key']}")