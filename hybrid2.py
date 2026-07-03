import hashlib
import random

# --------------------------
# Poseidon Hash (Simulation)
# --------------------------

class PoseidonHash:
    def __init__(self, prime=21888242871839275222246405745257275088548364400416034343698204186575808495617):
        self.p = prime
        self.rounds = 8

    def sbox(self, x):
        return pow(x, 5, self.p)

    def hash(self, inputs):
        state = sum(inputs) % self.p

        for i in range(self.rounds):
            state = self.sbox(state + i)

        return state


# --------------------------
# ATHOS PQ Signature (Simulation)
# --------------------------

class ATHOS:
    def keygen(self):
        sk = random.randint(10**10, 10**15)
        pk = hashlib.sha256(str(sk).encode()).hexdigest()
        return pk, sk


    def sign(self, message, sk):
        data = str(message) + str(sk)
        return hashlib.sha256(data.encode()).hexdigest()


    def verify(self, message, signature, sk):
        expected = hashlib.sha256(
            (str(message) + str(sk)).encode()
        ).hexdigest()

        return expected == signature


# --------------------------
# PIANIST Proof Layer
# --------------------------

class PIANIST:

    def __init__(self):
        self.poseidon = PoseidonHash()
        self.athos = ATHOS()


    def generate_proof(self, witness):

        # Step 1: Poseidon Commitment
        commitment = self.poseidon.hash(witness)


        # Step 2: ATHOS Keys
        public_key, secret_key = self.athos.keygen()


        # Step 3: Sign commitment
        signature = self.athos.sign(
            commitment,
            secret_key
        )

        proof = {
            "commitment": commitment,
            "signature": signature,
            "public_key": public_key,
            "secret_key": secret_key
        }

        return proof


    def verify_proof(self, witness, proof):

        # Recalculate commitment
        new_commitment = self.poseidon.hash(witness)


        if new_commitment != proof["commitment"]:
            return False, "Commitment mismatch"


        valid_signature = self.athos.verify(
            proof["commitment"],
            proof["signature"],
            proof["secret_key"]
        )

        if not valid_signature:
            return False, "ATHOS signature invalid"


        return True, "PIANIST + Poseidon + ATHOS proof verified"



# --------------------------
# Main Program
# --------------------------

def main():

    print("\nPIANIST + Poseidon + ATHOS Simulation")

    n = int(input("Number of witness values: "))

    witness = []

    for i in range(n):
        x = int(input(f"Witness {i+1}: "))
        witness.append(x)


    system = PIANIST()


    proof = system.generate_proof(witness)


    print("\nGenerated Proof")
    print("-------------------")

    for k, v in proof.items():
        print(k, ":", v)


    print("\nVerification Stage")
    print("-------------------")

    choice = input(
        "Verify with same witness? (y/n): "
    )


    if choice.lower() == "y":
        verify_data = witness

    else:
        verify_data = []

        for i in range(n):
            x = int(
                input(f"Enter verification witness {i+1}: ")
            )
            verify_data.append(x)


    status, message = system.verify_proof(
        verify_data,
        proof
    )


    print("\nResult")
    print("-------------------")
    print(message)


if __name__ == "__main__":
    main()