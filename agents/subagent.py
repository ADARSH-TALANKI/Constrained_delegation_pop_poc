from agents.did_manager import create_agent_identity


class SubAgent:

    def __init__(self):

        identity = create_agent_identity()

        self.did = identity["did"]

        self.public_key = identity["public_key"]

        self.private_key = identity["private_key"]

        self.vc = None

        self.permissions = []

    def display_info(self):

        print("\n=== SUB AGENT ===")

        print(f"DID : {self.did}")

        print(f"Permissions : {self.permissions}")
        

if __name__ == "__main__":

    subagent = SubAgent()

    subagent.display_info()