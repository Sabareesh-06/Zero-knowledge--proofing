import random

class WorkerNode:
    def __init__(self, node_id, trace, field_mod):
        self.node_id = node_id
        self.trace = trace
        self.field_mod = field_mod

    def compute_local_commitment(self):
        return sum(x * x for x in self.trace) % self.field_mod

    def evaluate_at_challenge(self, alpha):
        val = 0
        for i, coef in enumerate(self.trace):
            val = (val + coef * pow(alpha, i, self.field_mod)) % self.field_mod
        proof = (val * 42) % self.field_mod 
        return val, proof

class MasterCoordinator:
    def __init__(self, workers, field_mod):
        self.workers = workers
        self.field_mod = field_mod

    def verify_and_aggregate(self, alpha, beta):
        evals = []
        for w in self.workers:
            val, prf = w.evaluate_at_challenge(alpha)
            if prf != (val * 42) % self.field_mod:
                return None
            evals.append(val)
            
        global_val = 0
        for i, val in enumerate(evals):
            lagrange_y = pow(beta, i, self.field_mod)
            global_val = (global_val + lagrange_y * val) % self.field_mod
            
        return global_val

def test_pianist_successful_aggregation():
    p = 9973
    w1 = WorkerNode(0, [10, 20, 30], p)
    w2 = WorkerNode(1, [15, 25, 35], p)
    
    master = MasterCoordinator([w1, w2], p)
    res = master.verify_and_aggregate(alpha=3, beta=5)
    
    assert res is not None
    print(f"Test Successful Aggregation Passed: {res}")

def test_pianist_malicious_worker():
    p = 9973
    w1 = WorkerNode(0, [10, 20, 30], p)
    w2 = WorkerNode(1, [15, 25, 35], p)
    
    def bad_evaluate(alpha):
        return 1234, 5678
    w2.evaluate_at_challenge = bad_evaluate
    
    master = MasterCoordinator([w1, w2], p)
    res = master.verify_and_aggregate(alpha=3, beta=5)
    
    assert res is None
    print("Test Malicious Worker Detection Passed: (Proof generation aborted successfully)")

def test_pianist_identity_at_zero():
    p = 9973
    w1 = WorkerNode(0, [5, 0, 0], p)
    w2 = WorkerNode(1, [10, 0, 0], p)
    
    master = MasterCoordinator([w1, w2], p)
    res = master.verify_and_aggregate(alpha=0, beta=2)
    
    expected = (5 * pow(2, 0, p) + 10 * pow(2, 1, p)) % p
    assert res == expected
    print(f"Test Identity Point Passed: {res} == {expected}")

if __name__ == "__main__":
    test_pianist_successful_aggregation()
    test_pianist_malicious_worker()
    test_pianist_identity_at_zero()