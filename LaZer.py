import numpy as np

class LazerCryptoEngine:
    def __init__(self, n, q, bound_b):
        self.n = n
        self.q = q
        self.bound_b = bound_b

    def generate_random_poly(self, low, high):
        return np.random.randint(low, high, size=self.n, dtype=np.int64)

    def poly_add(self, poly1, poly2):
        return np.mod(poly1 + poly2, self.q)

    def poly_sub(self, poly1, poly2):
        return np.mod(poly1 - poly2, self.q)

    def poly_mul_negacyclic(self, p1, p2):
        result = np.zeros(self.n, dtype=np.int64)
        for i in range(self.n):
            for j in range(self.n):
                idx = i + j
                if idx < self.n:
                    result[idx] = (result[idx] + p1[i] * p2[j]) % self.q
                else:
                    result[idx - self.n] = (result[idx - self.n] - p1[i] * p2[j]) % self.q
        return np.mod(result, self.q)

    def check_bound(self, poly):
        half_q = self.q // 2
        for coef in poly:
            signed_coef = coef - self.q if coef > half_q else coef
            if abs(signed_coef) > self.bound_b:
                return False
        return True

class LazerProver:
    def __init__(self, engine, public_a, secret_s):
        self.engine = engine
        self.public_a = public_a
        self.secret_s = secret_s

    def prove(self):
        for attempt in range(100):
            y = self.engine.generate_random_poly(-10, 11)
            commitment_w = self.engine.poly_mul_negacyclic(self.public_a, y)
            
            challenge_c = np.zeros(self.engine.n, dtype=np.int64)
            challenge_c[0] = 1
            challenge_c[1] = -1
            
            cs = self.engine.poly_mul_negacyclic(challenge_c, self.secret_s)
            z = self.engine.poly_add(y, cs)
            
            if self.engine.check_bound(z):
                return commitment_w, challenge_c, z
        return None

class LazerVerifier:
    def __init__(self, engine, public_a, public_t):
        self.engine = engine
        self.public_a = public_a
        self.public_t = public_t

    def verify(self, commitment_w, challenge_c, z):
        if not self.engine.check_bound(z):
            return False
            
        az = self.engine.poly_mul_negacyclic(self.public_a, z)
        tc = self.engine.poly_mul_negacyclic(self.public_t, challenge_c)
        rhs = self.engine.poly_add(commitment_w, tc)
        
        return np.array_equal(az, rhs)

def test_lazer_proof_system():
    n = 8
    q = 8380417
    bound = 500
    
    engine = LazerCryptoEngine(n, q, bound)
    
    public_a = engine.generate_random_poly(0, q)
    secret_s = engine.generate_random_poly(-3, 4)
    public_t = engine.poly_mul_negacyclic(public_a, secret_s)
    
    prover = LazerProver(engine, public_a, secret_s)
    verifier = LazerVerifier(engine, public_a, public_t)
    
    proof = prover.prove()
    assert proof is not None, "Failed during rejection sampling window"
    
    commitment_w, challenge_c, z = proof
    is_valid = verifier.verify(commitment_w, challenge_c, z)
    
    assert is_valid == True
    print("Test Lazer Functional Validation Passed.")
    print(f"Generated Short Unbounded Mask Vector (z):\n {z}")

if __name__ == "__main__":
    test_lazer_proof_system()