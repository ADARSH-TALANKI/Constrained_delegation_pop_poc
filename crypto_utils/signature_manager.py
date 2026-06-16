import json

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder


def sign_data(data, private_key_hex):

    signing_key = SigningKey(
        private_key_hex,
        encoder=HexEncoder
    )

    message = json.dumps(
        data,
        sort_keys=True
    ).encode()

    signed = signing_key.sign(message)

    return signed.signature.hex()


if __name__ == "__main__":

    sample_data = {
        "name": "SOC Agent",
        "permission": "read_logs"
    }

    from crypto_utils.key_manager import generate_keypair

    keys = generate_keypair()

    signature = sign_data(
        sample_data,
        keys["private_key"]
    )

    print(signature)