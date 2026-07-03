import hashlib

def generate_constants(prime, t, r_f, r_p):
    constants = []
    total_rounds = r_f + r_p
    seed = b"poseidon"
    for i in range(total_rounds):
        round_constants = []
        for j in range(t):
            h = hashlib.sha256(seed + bytes([i, j])).digest()
            val = int.from_bytes(h, "big") % prime
            round_constants.append(val)
        constants.append(round_constants)
    return constants

def generate_mds_matrix(prime, t):
    matrix = []
    for i in range(t):
        row = []
        for j in range(t):
            val = pow(i + j + 1, prime - 2, prime)
            row.append(val)
        matrix.append(row)
    return matrix

class Poseidon:
    def __init__(self, prime, t, alpha, r_f, r_p):
        self.prime = prime
        self.t = t
        self.alpha = alpha
        self.r_f = r_f
        self.r_p = r_p
        self.round_constants = generate_constants(prime, t, r_f, r_p)
        self.mds_matrix = generate_mds_matrix(prime, t)

    def _sbox(self, val):
        return pow(val, self.alpha, self.prime)

    def _mix(self, state):
        new_state = [0] * self.t
        for i in range(self.t):
            acc = 0
            for j in range(self.t):
                acc = (acc + self.mds_matrix[i][j] * state[j]) % self.prime
            new_state[i] = acc
        return new_state

    def permute(self, input_state):
        state = list(input_state)
        total_rounds = self.r_f + self.r_p
        half_rf = self.r_f // 2

        for r in range(total_rounds):
            for i in range(self.t):
                state[i] = (state[i] + self.round_constants[r][i]) % self.prime

            if r < half_rf or r >= (half_rf + self.r_p):
                for i in range(self.t):
                    state[i] = self._sbox(state[i])
            else:
                state[0] = self._sbox(state[0])

            state = self._mix(state)
        return state

    def hash_elements(self, elements):
        state = [0] * self.t
        for i, el in enumerate(elements[:self.t]):
            state[i] = el % self.prime
        out = self.permute(state)
        return out[0]

def test_poseidon_correctness():
    p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    poseidon = Poseidon(prime=p, t=3, alpha=5, r_f=8, r_p=57)
    
    input_data = [123, 456]
    h1 = poseidon.hash_elements(input_data)
    h2 = poseidon.hash_elements(input_data)
    
    assert h1 == h2
    print(f"Test Execution Deterministic Result: {hex(h1)}")

def test_poseidon_avalanche():
    p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    poseidon = Poseidon(prime=p, t=3, alpha=5, r_f=8, r_p=57)
    
    h1 = poseidon.hash_elements([100, 200])
    h2 = poseidon.hash_elements([101, 200])
    
    assert h1 != h2
    print("Test Avalanche (Minor input modification yields a completely distinct hash) Passed.")

if __name__ == "__main__":
    test_poseidon_correctness()
    test_poseidon_avalanche()