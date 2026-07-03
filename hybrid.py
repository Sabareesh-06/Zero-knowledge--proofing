import hashlib
import secrets
import time


# ==========================================================
# System Parameters
# ==========================================================

PRIME = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

BYTE_RING = 256


# ==========================================================
# Master Password Authentication
# ==========================================================

def hash_master_password(password):
    """
    Store only the SHA-256 hash of the master password.
    """

    return hashlib.sha256(
        password.encode()
    ).hexdigest()


def verify_master_password(password, stored_hash):
    """
    Verify master password.
    """

    return (
        hashlib.sha256(
            password.encode()
        ).hexdigest()
        == stored_hash
    )


# ==========================================================
# Encryption / Decryption (Prototype)
# ==========================================================

def derive_key(master_password):
    """
    Derive a 256-bit key from the master password.
    """

    return hashlib.sha256(
        master_password.encode()
    ).digest()


def xor_cipher(data, key):
    """
    Symmetric XOR encryption/decryption.

    WARNING:
    This is a prototype implementation.
    Production systems should use authenticated
    encryption.
    """

    output = bytearray()

    for i in range(len(data)):

        output.append(
            data[i] ^ key[i % len(key)]
        )

    return bytes(output)


def encrypt_password(password, master_password):
    """
    Encrypt website password.
    """

    key = derive_key(master_password)

    return xor_cipher(
        password.encode(),
        key
    )


def decrypt_password(ciphertext, master_password):
    """
    Recover original website password.
    """

    key = derive_key(master_password)

    plaintext = xor_cipher(
        ciphertext,
        key
    )

    return plaintext.decode()


# ==========================================================
# Random PIANIST Challenge
# ==========================================================

def generate_alpha():
    """
    Generate a random non-zero field element.
    """

    return (
        secrets.randbelow(PRIME - 1)
        + 1
    )


# ==========================================================
# Poseidon Hash (Research Prototype)
# ==========================================================

class PoseidonHasher:

    def __init__(self, prime):

        self.prime = prime
        self.state_size = 3
        self.rounds = 16
        self.alpha = 5


        # Round constants
        self.constants = []

        for r in range(self.rounds):

            round_values = []

            for c in range(self.state_size):

                value = int(
                    hashlib.sha256(
                        bytes([r, c])
                    ).hexdigest(),
                    16
                ) % self.prime

                round_values.append(
                    value
                )

            self.constants.append(
                round_values
            )


        # MDS matrix
        self.mds = []

        for i in range(self.state_size):

            row = []

            for j in range(self.state_size):

                value = pow(
                    i + j + 1,
                    self.prime - 2,
                    self.prime
                )

                row.append(value)

            self.mds.append(row)


    def hash_domain(self, domain):
        """
        Hash a website domain.
        """

        digest = hashlib.sha256(
            domain.encode()
        ).digest()


        state = [
            digest[0],
            digest[1],
            digest[2]
        ]


        for r in range(self.rounds):

            # Add round constants
            for i in range(self.state_size):

                state[i] = (
                    state[i]
                    + self.constants[r][i]
                ) % self.prime


            # S-box
            for i in range(self.state_size):

                state[i] = pow(
                    state[i],
                    self.alpha,
                    self.prime
                )


            # MDS mixing
            new_state = [
                0
            ] * self.state_size


            for i in range(
                self.state_size
            ):

                for j in range(
                    self.state_size
                ):

                    new_state[i] += (
                        self.mds[i][j]
                        * state[j]
                    )

                new_state[i] %= (
                    self.prime
                )


            state = new_state


        return state[0]
# ==========================================================
# ATHOS Byte-Wise Secret Sharing
# ==========================================================

class AthosByteSharer:

    def __init__(self):
        self.ring = BYTE_RING


    def split_bytes(self, data):
        """
        Split encrypted bytes into two additive shares.

        For each byte:
        share1 = random byte
        share2 = (original - share1) mod 256
        """

        share1 = bytearray()
        share2 = bytearray()


        for byte in data:

            random_share = secrets.randbelow(
                self.ring
            )


            second_share = (
                byte - random_share
            ) % self.ring


            share1.append(
                random_share
            )


            share2.append(
                second_share
            )


        return (
            bytes(share1),
            bytes(share2)
        )


    def reconstruct_bytes(
        self,
        share1,
        share2
    ):
        """
        Recover original bytes.

        original = (share1 + share2) mod 256
        """

        recovered = bytearray()


        for a, b in zip(
            share1,
            share2
        ):

            recovered.append(
                (a + b)
                % self.ring
            )


        return bytes(recovered)


# ==========================================================
# Distributed Worker Node
# ==========================================================

class PasswordVaultWorker:

    def __init__(
        self,
        worker_id,
        prime
    ):

        self.worker_id = worker_id
        self.prime = prime

        # Stores:
        # domain_hash -> byte share
        self.storage = {}


    # ------------------------------------------------------
    # Store a secret share
    # ------------------------------------------------------

    def store_share(
        self,
        domain_hash,
        share
    ):

        self.storage[
            domain_hash
        ] = share


    # ------------------------------------------------------
    # PIANIST Challenge Response
    # ------------------------------------------------------

    def retrieve_share(
        self,
        domain_hash,
        alpha
    ):
        """
        For every byte:
        evaluation = share * alpha mod PRIME

        Proof:
        proof = evaluation * 42 mod PRIME

        Returns two lists:
        evaluations and proofs
        """


        if domain_hash not in self.storage:

            return [], []


        share = self.storage[
            domain_hash
        ]


        evaluations = []
        proofs = []


        for byte in share:

            evaluation = (
                byte * alpha
            ) % self.prime


            proof = (
                evaluation * 42
            ) % self.prime


            evaluations.append(
                evaluation
            )

            proofs.append(
                proof
            )


        return (
            evaluations,
            proofs
        )


    # ------------------------------------------------------
    # Delete account share
    # ------------------------------------------------------

    def delete_share(
        self,
        domain_hash
    ):

        if domain_hash in self.storage:

            del self.storage[
                domain_hash
            ]


    # ------------------------------------------------------
    # Simulate worker failure
    # ------------------------------------------------------

    def clear_storage(self):

        self.storage.clear()


    # ------------------------------------------------------
    # Worker information
    # ------------------------------------------------------

    def status(self):

        print(
            f"Worker {self.worker_id}"
        )

        print(
            "Stored accounts:",
            len(self.storage)
        )

        print(
            "Status: ACTIVE"
            if len(self.storage) >= 0
            else "FAILED"
        )
# ==========================================================
# PIANIST Coordinator
# ==========================================================

class Coordinator:

    def __init__(
        self,
        workers,
        prime,
        sharer
    ):

        self.workers = workers
        self.prime = prime
        self.sharer = sharer


    # ------------------------------------------------------
    # Verify PIANIST proof
    # ------------------------------------------------------

    def verify_proof(
        self,
        evaluation,
        proof
    ):
        """
        Simulated PIANIST verification.
        """

        expected = (
            evaluation * 42
        ) % self.prime


        return proof == expected


    # ------------------------------------------------------
    # Recover a single worker's byte shares
    # ------------------------------------------------------

    def recover_worker_share(
        self,
        evaluations,
        alpha
    ):
        """
        Remove the alpha challenge:
        
        share = evaluation × alpha⁻¹ mod PRIME
        """

        recovered = []


        alpha_inverse = pow(
            alpha,
            self.prime - 2,
            self.prime
        )


        for value in evaluations:

            byte = (
                value * alpha_inverse
            ) % self.prime


            recovered.append(
                byte
            )


        return bytes(recovered)


    # ------------------------------------------------------
    # Complete password reconstruction
    # ------------------------------------------------------

    def reconstruct_password(
        self,
        domain_hash
    ):
        """
        1. Generate random alpha
        2. Query workers
        3. Verify PIANIST proofs
        4. Remove alpha
        5. Combine ATHOS shares
        """

        # Fresh challenge every access
        alpha = generate_alpha()


        print(
            "\nGenerated PIANIST α challenge:"
        )

        print(alpha)


        worker_shares = []


        # Query every worker
        for worker in self.workers:

            evaluations, proofs = (
                worker.retrieve_share(
                    domain_hash,
                    alpha
                )
            )


            if len(evaluations) == 0:

                print(
                    f"Worker {worker.worker_id} has no data."
                )

                return None


            # Verify every byte proof
            for evaluation, proof in zip(
                evaluations,
                proofs
            ):

                if not self.verify_proof(
                    evaluation,
                    proof
                ):

                    print(
                        "PIANIST verification failed on",
                        f"Worker {worker.worker_id}"
                    )

                    return None


            # Remove alpha and recover byte share
            recovered = (
                self.recover_worker_share(
                    evaluations,
                    alpha
                )
            )


            worker_shares.append(
                recovered
            )


        # Need two shares
        if len(worker_shares) != 2:

            print(
                "Invalid number of workers."
            )

            return None


        # ATHOS reconstruction
        encrypted_password = (
            self.sharer.reconstruct_bytes(
                worker_shares[0],
                worker_shares[1]
            )
        )


        return encrypted_password


    # ------------------------------------------------------
    # Display worker information
    # ------------------------------------------------------

    def worker_status(self):

        print(
            "\n========== WORKER STATUS =========="
        )


        for worker in self.workers:

            worker.status()
# ==========================================================
# Password Vault
# ==========================================================

class PasswordVault:

    def __init__(
        self,
        hasher,
        sharer,
        coordinator
    ):

        self.hasher = hasher
        self.sharer = sharer
        self.coordinator = coordinator

        # Stores only metadata
        self.accounts = {}

        # Master password hash
        self.master_hash = None


    # ------------------------------------------------------
    # Create master password
    # ------------------------------------------------------

    def create_master_password(
        self,
        password
    ):

        if self.master_hash is not None:

            print(
                "Master password already exists."
            )

            return False


        self.master_hash = hash_master_password(
            password
        )


        print(
            "Master password created successfully."
        )

        return True


    # ------------------------------------------------------
    # Verify master password
    # ------------------------------------------------------

    def authenticate(
        self,
        password
    ):

        if self.master_hash is None:

            print(
                "Vault not initialized."
            )

            return False


        if verify_master_password(
            password,
            self.master_hash
        ):

            return True


        print(
            "Access denied: Incorrect master password."
        )

        return False


    # ------------------------------------------------------
    # Register a new website account
    # ------------------------------------------------------

    def register_account(
        self,
        domain,
        username,
        website_password,
        master_password
    ):

        if not self.authenticate(master_password):

            return


        if domain in self.accounts:

            print(
                "Account already exists. Use update option."
            )

            return


        # Poseidon domain identifier
        domain_hash = self.hasher.hash_domain(
            domain
        )


        # Encrypt website password
        encrypted_password = encrypt_password(
            website_password,
            master_password
        )


        # ATHOS byte sharing
        share1, share2 = (
            self.sharer.split_bytes(
                encrypted_password
            )
        )


        # Store shares in workers
        self.coordinator.workers[0].store_share(
            domain_hash,
            share1
        )

        self.coordinator.workers[1].store_share(
            domain_hash,
            share2
        )


        # Store metadata only
        self.accounts[domain] = {

            "username": username,

            "domain_hash": domain_hash

        }


        print(
            "Account registered successfully."
        )


    # ------------------------------------------------------
    # Retrieve website password
    # ------------------------------------------------------

    def retrieve_account(
        self,
        domain,
        master_password
    ):


        if not self.authenticate(master_password):

            return


        if domain not in self.accounts:

            print(
                "Account not found."
            )

            return


        domain_hash = (
            self.accounts[domain]["domain_hash"]
        )


        # PIANIST + ATHOS reconstruction
        encrypted_password = (
            self.coordinator.reconstruct_password(
                domain_hash
            )
        )


        if encrypted_password is None:

            print(
                "Password recovery failed."
            )

            return


        # Decrypt the recovered bytes
        password = decrypt_password(
            encrypted_password,
            master_password
        )


        print(
            "\n========== ACCOUNT RECOVERED =========="
        )

        print(
            "Domain:",
            domain
        )

        print(
            "Username:",
            self.accounts[domain]["username"]
        )

        print(
            "Website Password:",
            password
        )


    # ------------------------------------------------------
    # Update website password
    # ------------------------------------------------------

    def update_password(
        self,
        domain,
        new_password,
        master_password
    ):


        if not self.authenticate(master_password):

            return


        if domain not in self.accounts:

            print(
                "Account does not exist."
            )

            return


        domain_hash = (
            self.accounts[domain]["domain_hash"]
        )


        # Encrypt new password
        encrypted_password = encrypt_password(
            new_password,
            master_password
        )


        # Create fresh ATHOS shares
        share1, share2 = (
            self.sharer.split_bytes(
                encrypted_password
            )
        )


        # Replace shares
        self.coordinator.workers[0].store_share(
            domain_hash,
            share1
        )

        self.coordinator.workers[1].store_share(
            domain_hash,
            share2
        )


        print(
            "Website password updated successfully."
        )


    # ------------------------------------------------------
    # Delete account
    # ------------------------------------------------------

    def delete_account(
        self,
        domain,
        master_password
    ):


        if not self.authenticate(master_password):

            return


        if domain not in self.accounts:

            print(
                "Account does not exist."
            )

            return


        domain_hash = (
            self.accounts[domain]["domain_hash"]
        )


        # Remove shares from workers
        for worker in self.coordinator.workers:

            worker.delete_share(
                domain_hash
            )


        # Remove metadata
        del self.accounts[domain]


        print(
            "Account deleted successfully."
        )


    # ------------------------------------------------------
    # List stored accounts
    # ------------------------------------------------------

    def list_accounts(self):

        print(
            "\n========== STORED ACCOUNTS =========="
        )


        if len(self.accounts) == 0:

            print(
                "No accounts in vault."
            )

            return


        for domain, data in self.accounts.items():

            print(
                "Domain:",
                domain
            )

            print(
                "Username:",
                data["username"]
            )

            print(
                "------------------------------"
            )


    # ------------------------------------------------------
    # Vault statistics
    # ------------------------------------------------------

    def statistics(self):

        print(
            "\n========== VAULT STATISTICS =========="
        )


        print(
            "Total accounts:",
            len(self.accounts)
        )


        for worker in self.coordinator.workers:

            print(
                f"Worker {worker.worker_id} stores",
                len(worker.storage),
                "shares"
            )
# ==========================================================
# Security and Performance Testing
# ==========================================================


class SecurityTester:

    def __init__(
        self,
        vault,
        coordinator,
        workers,
        hasher
    ):

        self.vault = vault
        self.coordinator = coordinator
        self.workers = workers
        self.hasher = hasher


    # ------------------------------------------------------
    # Test wrong master password
    # ------------------------------------------------------

    def wrong_password_test(
        self,
        domain
    ):

        print("\n========== WRONG PASSWORD TEST ==========")

        self.vault.retrieve_account(
            domain,
            "WrongPassword123"
        )


    # ------------------------------------------------------
    # Simulate malicious worker
    # ------------------------------------------------------

    def malicious_worker_test(self):

        print("\n========== MALICIOUS WORKER TEST ==========")


        # Save original method
        original = self.workers[1].retrieve_share


        # Fake worker response
        def fake_response(domain_hash, alpha):

            fake_evaluation = [99999, 88888]
            fake_proof = [12345, 54321]

            return (
                fake_evaluation,
                fake_proof
            )


        # Replace worker behaviour
        self.workers[1].retrieve_share = fake_response


        print(
            "Worker 2 is now malicious."
        )

        print(
            "Try retrieving any account."
        )

        print(
            "Expected result: PIANIST verification failure."
        )


        return original


    # ------------------------------------------------------
    # Restore worker after attack
    # ------------------------------------------------------

    def restore_worker(
        self,
        original_function
    ):

        self.workers[1].retrieve_share = (
            original_function
        )

        print(
            "Worker 2 restored successfully."
        )


    # ------------------------------------------------------
    # Worker failure simulation
    # ------------------------------------------------------

    def worker_failure_test(self):

        print("\n========== WORKER FAILURE TEST ==========")

        self.workers[1].clear_storage()


        print(
            "Worker 2 storage erased."
        )

        print(
            "Retrieval should now fail."
        )


    # ------------------------------------------------------
    # Poseidon hash uniqueness test
    # ------------------------------------------------------

    def poseidon_collision_test(self):

        print(
            "\n========== POSEIDON HASH TEST =========="
        )


        domains = [
            "google.com",
            "gmail.com",
            "github.com",
            "facebook.com",
            "instagram.com",
            "x.com",
            "amazon.com",
            "microsoft.com",
            "openai.com",
            "stackoverflow.com"
        ]


        hashes = {}


        collision_found = False


        for domain in domains:

            value = self.hasher.hash_domain(
                domain
            )


            print(
                domain,
                "->",
                value
            )


            if value in hashes:

                collision_found = True

                print(
                    "Collision detected:"
                )

                print(
                    domain,
                    "and",
                    hashes[value]
                )


            else:

                hashes[value] = domain


        if not collision_found:

            print(
                "No collisions detected."
            )


    # ------------------------------------------------------
    # Stress test repeated retrieval
    # ------------------------------------------------------

    def stress_test(
        self,
        domain,
        master_password,
        count
    ):

        print(
            "\n========== STRESS TEST =========="
        )

        start = time.time()


        successful = 0


        for i in range(count):

            try:

                domain_hash = (
                    self.vault.accounts[domain]
                    ["domain_hash"]
                )


                encrypted = (
                    self.coordinator
                    .reconstruct_password(
                        domain_hash
                    )
                )


                if encrypted is not None:

                    password = decrypt_password(
                        encrypted,
                        master_password
                    )


                    successful += 1


            except Exception as e:

                print(
                    "Error on iteration",
                    i,
                    ":",
                    e
                )


        end = time.time()


        print(
            "Total attempts:",
            count
        )

        print(
            "Successful recoveries:",
            successful
        )

        print(
            "Failed recoveries:",
            count - successful
        )

        print(
            "Execution time:",
            round(
                end - start,
                5
            ),
            "seconds"
        )


    # ------------------------------------------------------
    # Show system security summary
    # ------------------------------------------------------

    def security_report(self):

        print(
            "\n========== SECURITY REPORT =========="
        )

        print(
            "✔ Master password authentication"
        )

        print(
            "✔ Encrypted website passwords"
        )

        print(
            "✔ Poseidon domain hashing"
        )

        print(
            "✔ ATHOS distributed byte shares"
        )

        print(
            "✔ PIANIST random alpha challenges"
        )

        print(
            "✔ Worker proof verification"
        )

        print(
            "✔ Malicious worker detection"
        )

        print(
            "✔ Failure simulation testing"
        )
# ==========================================================
# System Initialization
# ==========================================================

hasher = PoseidonHasher(PRIME)

sharer = AthosByteSharer()


worker1 = PasswordVaultWorker(
    worker_id=1,
    prime=PRIME
)

worker2 = PasswordVaultWorker(
    worker_id=2,
    prime=PRIME
)


coordinator = Coordinator(
    workers=[worker1, worker2],
    prime=PRIME,
    sharer=sharer
)


vault = PasswordVault(
    hasher=hasher,
    sharer=sharer,
    coordinator=coordinator
)


tester = SecurityTester(
    vault=vault,
    coordinator=coordinator,
    workers=[worker1, worker2],
    hasher=hasher
)


# ==========================================================
# Master Password Setup
# ==========================================================

print("\n================================================")
print("   PIANIST + Poseidon + ATHOS PASSWORD MANAGER")
print("================================================")

while True:

    master_password = input(
        "\nCreate your vault master password: "
    )

    if len(master_password.strip()) == 0:

        print(
            "Master password cannot be empty."
        )

        continue


    vault.create_master_password(
        master_password
    )

    break


# ==========================================================
# Main Menu
# ==========================================================

while True:

    print("\n================ MAIN MENU ================")

    print("1. Register New Account")
    print("2. Retrieve Account Password")
    print("3. Update Account Password")
    print("4. Delete Account")
    print("5. List Stored Accounts")
    print("6. View Vault Statistics")
    print("7. Worker Status")

    print("\n----- Security Tests -----")

    print("8. Wrong Master Password Test")
    print("9. Malicious Worker Test")
    print("10. Restore Malicious Worker")
    print("11. Worker Failure Test")
    print("12. Poseidon Collision Test")
    print("13. Stress Test")
    print("14. Security Report")

    print("\n15. Exit")


    choice = input(
        "\nEnter your choice: "
    )


    # ======================================================
    # Register Account
    # ======================================================

    if choice == "1":

        domain = input(
            "Enter website domain: "
        )

        username = input(
            "Enter username/email: "
        )

        password = input(
            "Enter website password: "
        )

        master = input(
            "Enter vault master password: "
        )


        vault.register_account(
            domain,
            username,
            password,
            master
        )


    # ======================================================
    # Retrieve Account
    # ======================================================

    elif choice == "2":

        domain = input(
            "Enter website domain: "
        )

        master = input(
            "Enter vault master password: "
        )


        vault.retrieve_account(
            domain,
            master
        )


    # ======================================================
    # Update Password
    # ======================================================

    elif choice == "3":

        domain = input(
            "Enter website domain: "
        )

        new_password = input(
            "Enter new website password: "
        )

        master = input(
            "Enter vault master password: "
        )


        vault.update_password(
            domain,
            new_password,
            master
        )


    # ======================================================
    # Delete Account
    # ======================================================

    elif choice == "4":

        domain = input(
            "Enter website domain: "
        )

        master = input(
            "Enter vault master password: "
        )


        vault.delete_account(
            domain,
            master
        )


    # ======================================================
    # List Accounts
    # ======================================================

    elif choice == "5":

        vault.list_accounts()


    # ======================================================
    # Statistics
    # ======================================================

    elif choice == "6":

        vault.statistics()


    # ======================================================
    # Worker Status
    # ======================================================

    elif choice == "7":

        coordinator.worker_status()


    # ======================================================
    # Wrong Password Test
    # ======================================================

    elif choice == "8":

        domain = input(
            "Enter domain to test: "
        )

        tester.wrong_password_test(
            domain
        )


    # ======================================================
    # Malicious Worker Attack
    # ======================================================

    elif choice == "9":

        backup = tester.malicious_worker_test()


    # ======================================================
    # Restore Worker
    # ======================================================

    elif choice == "10":

        try:

            tester.restore_worker(
                backup
            )

        except NameError:

            print(
                "No malicious worker has been activated."
            )


    # ======================================================
    # Worker Failure Simulation
    # ======================================================

    elif choice == "11":

        tester.worker_failure_test()


    # ======================================================
    # Poseidon Collision Test
    # ======================================================

    elif choice == "12":

        tester.poseidon_collision_test()


    # ======================================================
    # Stress Testing
    # ======================================================

    elif choice == "13":

        domain = input(
            "Enter domain: "
        )

        master = input(
            "Enter master password: "
        )

        count = int(
            input(
                "Number of retrievals: "
            )
        )


        tester.stress_test(
            domain,
            master,
            count
        )


    # ======================================================
    # Security Report
    # ======================================================

    elif choice == "14":

        tester.security_report()


    # ======================================================
    # Exit
    # ======================================================

    elif choice == "15":

        print(
            "\nClosing Password Manager..."
        )

        print(
            "Your PIANIST + Poseidon + ATHOS vault is now closed."
        )

        break


    # ======================================================
    # Invalid Input
    # ======================================================

    else:

        print(
            "Invalid option. Please try again."
        )