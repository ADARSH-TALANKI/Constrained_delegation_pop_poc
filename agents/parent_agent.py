from agents.did_manager import create_agent_identity


class ParentAgent:

    def __init__(self):

        identity = create_agent_identity()

        self.did = identity["did"]
        self.public_key = identity["public_key"]
        self.private_key = identity["private_key"]

        # Will come later from VC
        self.permissions = []

        # Will come later from Issuer
        self.vc = None

    def display_info(self):

        print("\n=== PARENT AGENT ===")
        print(f"DID         : {self.did}")
        print(f"Permissions : {self.permissions}")
        print(f"VC          : {self.vc}")


if __name__ == "__main__":

    parent = ParentAgent()

    parent.display_info()