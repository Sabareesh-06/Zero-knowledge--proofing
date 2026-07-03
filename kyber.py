import numpy as np
import hashlib

class NTTModule:
    def __init__(self, n=256, q=3329):
        self.n = n
        self.q = q
        self.psi = self._find_primitive_root()
        self.inv_n = pow(self.n, self.q - 2, self.q)

    def _find_primitive_root(self):
        for r in range(2, self.q):
            if pow(r, 2 * self.n, self.q) == 1:
                is_prim = True
                for factor in [2, self.n]:
                    if pow(r, (2 * self.n) // factor, self.q) == 1:
                        is_prim = False
                        break
                if is_prim:
                    return r
        return 2

    def ntt(self, poly):
        a = list(poly) + [0] * (self.n - len(poly))
        t = self.n // 2
        m = 1
        while t >= 1:
            for i in range(m):
                start = i * 2 * t
                psi_pow = pow(self.psi, m + i, self.q)
                for j in range(t):
                    u = a[start + j]
                    v = (a[start + j + t] * psi_pow) % self.q
                    a[start + j] = (u + v) % self.q
                    a[start + j + t] = (u - v) % self.q
            t //= 2
            m *= 2
        return np.array(a, dtype=np.int64)

    def intt(self, poly_ntt):
        a = list(poly_ntt)
        t = 1
        m = self.n // 2
        while m >= 1:
            for i in range(m):
                start = i * 2 * t
                psi_pow = pow(self.psi, m + i, self.q)
                inv_psi = pow(psi_pow, self.q - 2, self.q)
                for j in range(t):
                    u = a[start + j]
                    v = a[start + j + t]
                    a[start + j] = (u + v) % self.q
                    a[start + j + t] = ((u - v) * inv_psi) % self.q
            t *= 2
            m //= 2
        for i in range(self.n):
            a[i] = (a[i] * self.inv_n) % self.q
        return np.array(a, dtype=np.int64)

class MLWECryptoEngine:
    def __init__(self, k=2, n=256, q=3329):
        self.k = k
        self.n = n
        self.q = q
        self.ntt_engine = NTTModule(n, q)

    def sample_cbd(self, eta=2):
        poly = np.zeros(self.n, dtype=np.int64)
        for i in range(self.n):
            a = sum(np.random.randint(0, 2) for _ in range(eta))
            b = sum(np.random.randint(0, 2) for _ in range(eta))
            poly[i] = (a - b) % self.q
        return poly

    def poly_add(self, p1, p2):
        return np.mod(p1 + p2, self.q)

    def poly_mul(self, p1, p2):
        p1_ntt = self.ntt_engine.ntt(p1)
        p2_ntt = self.ntt_engine.ntt(p2)
        res_ntt = (p1_ntt * p2_ntt) % self.q
        return self.ntt_engine.intt(res_ntt)

    def keygen(self):
        A = [[np.random.randint(0, self.q, self.n) for _ in range(self.k)] for _ in range(self.k)]
        s = [self.sample_cbd() for _ in range(self.k)]
        e = [self.sample_cbd() for _ in range(self.k)]
        
        t = []
        for i in range(self.k):
            acc = e[i]
            for j in range(self.k):
                prod = self.poly_mul(A[i][j], s[j])
                acc = self.poly_add(acc, prod)
            t.append(acc)
            
        return A, t, s

    def encapsulate(self, A, t):
        r = [self.sample_cbd() for _ in range(self.k)]
        e1 = [self.sample_cbd() for _ in range(self.k)]
        e2 = self.sample_cbd()
        
        u = []
        for i in range(self.k):
            acc = e1[i]
            for j in range(self.k):
                prod = self.poly_mul(A[j][i], r[j])
                acc = self.poly_add(acc, prod)
            u.append(acc)
            
        v_acc = e2
        for i in range(self.k):
            prod = self.poly_mul(t[i], r[i])
            v_acc = self.poly_add(v_acc, prod)
            
        msg_poly = np.zeros(self.n, dtype=np.int64)
        msg_poly[0] = self.q // 2
        v = self.poly_add(v_acc, msg_poly)
        
        return u, v

    def decapsulate(self, u, v, s):
        su_acc = np.zeros(self.n, dtype=np.int64)
        for i in range(self.k):
            prod = self.poly_mul(s[i], u[i])
            su_acc = self.poly_add(su_acc, prod)
            
        diff = np.mod(v - su_acc, self.q)
        half_q = self.q // 2
        
        return 1 if abs(int(diff[0]) - half_q) < half_q // 2 else 0

    def sign(self, A, s, message_bytes):
        half_q = self.q // 2
        for attempt in range(100):
            y = [np.random.randint(-100, 101, self.n) % self.q for _ in range(self.k)]
            
            w = []
            for i in range(self.k):
                acc = np.zeros(self.n, dtype=np.int64)
                for j in range(self.k):
                    prod = self.poly_mul(A[i][j], y[j])
                    acc = self.poly_add(acc, prod)
                w.append(acc)
                
            hasher = hashlib.sha256(message_bytes)
            for poly in w:
                hasher.update(poly.tobytes())
            h_val = int(hasher.hexdigest(), 16)
            
            c = np.zeros(self.n, dtype=np.int64)
            c[0] = 1 if (h_val % 2 == 0) else self.q - 1
            
            z = []
            safe = True
            for i in range(self.k):
                cs = self.poly_mul(c, s[i])
                zi = self.poly_add(y[i], cs)
                z.append(zi)
                
                for coef in zi:
                    signed_coef = coef - self.q if coef > half_q else coef
                    if abs(signed_coef) > 500:
                        safe = False
                        break
            if safe:
                return z, c
        return None

    def verify(self, A, t, z, c, message_bytes):
        half_q = self.q // 2
        for zi in z:
            for coef in zi:
                signed_coef = coef - self.q if coef > half_q else coef
                if abs(signed_coef) > 500:
                    return False
                    
        w_prime = []
        for i in range(self.k):
            az_acc = np.zeros(self.n, dtype=np.int64)
            for j in range(self.k):
                prod = self.poly_mul(A[i][j], z[j])
                az_acc = self.poly_add(az_acc, prod)
                
            tc = self.poly_mul(t[i], c)
            w_i = np.mod(az_acc - tc, self.q)
            w_prime.append(w_i)
            
        hasher = hashlib.sha256(message_bytes)
        for poly in w_prime:
            hasher.update(poly.tobytes())
        h_val = int(hasher.hexdigest(), 16)
        
        expected_c0 = 1 if (h_val % 2 == 0) else self.q - 1
        return c[0] == expected_c0

def test_pqc_kyber_kem_flow():
    engine = MLWECryptoEngine(k=2, n=256, q=3329)
    A, t, s = engine.keygen()
    u, v = engine.encapsulate(A, t)
    decrypted_bit = engine.decapsulate(u, v, s)
    assert decrypted_bit == 1
    print("Kyber KEM Execution Flow Passed.")

def test_pqc_dilithium_signature_flow():
    engine = MLWECryptoEngine(k=2, n=256, q=3329)
    A, t, s = engine.keygen()
    msg = b"Post-Quantum Cryptography Verification"
    z, c = engine.sign(A, s, msg)
    assert z is not None
    is_valid = engine.verify(A, t, z, c, msg)
    assert is_valid == True
    print("Dilithium Signature Execution Flow Passed.")

if __name__ == "__main__":
    test_pqc_kyber_kem_flow()
    test_pqc_dilithium_signature_flow()