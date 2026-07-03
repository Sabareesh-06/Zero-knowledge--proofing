import numpy as np

class AthosCompiler:
    def __init__(self, scale_factor, ring_modulo):
        self.scale_factor = scale_factor
        self.ring_modulo = ring_modulo

    def compile_to_fixed_point(self, float_array):
        multiplier = 2 ** self.scale_factor
        flat_fixed = [int(np.trunc(x * multiplier)) % self.ring_modulo for x in float_array.flatten()]
        return np.array(flat_fixed, dtype=object).reshape(float_array.shape)

    def generate_secret_shares(self, fixed_matrix):
        shape = fixed_matrix.shape
        flat_matrix = fixed_matrix.flatten()
        share_1 = np.array([int(np.random.randint(0, 2**30)) % self.ring_modulo for _ in flat_matrix], dtype=object)
        share_2 = np.array([(val - s1) % self.ring_modulo for val, s1 in zip(flat_matrix, share_1)], dtype=object)
        return share_1.reshape(shape), share_2.reshape(shape)

class MpcExecutionBackend:
    def __init__(self, scale_factor, ring_modulo):
        self.scale_factor = scale_factor
        self.ring_modulo = ring_modulo

    def secure_matrix_multiply(self, s1_a, s2_a, s1_b, s2_b):
        def matmul_pure(A, B):
            h, w_A = A.shape
            _, w_B = B.shape
            result = np.zeros((h, w_B), dtype=object)
            for i in range(h):
                for j in range(w_B):
                    acc = 0
                    for k in range(w_A):
                        acc = (acc + int(A[i, k]) * int(B[k, j])) % self.ring_modulo
                    result[i, j] = acc
            return result

        p1_local = matmul_pure(s1_a, s1_b)
        p2_local = matmul_pure(s2_a, s2_b)
        cross_1 = matmul_pure(s1_a, s2_b)
        cross_2 = matmul_pure(s2_a, s1_b)
        
        share_1 = (p1_local + cross_1) % self.ring_modulo
        share_2 = (p2_local + cross_2) % self.ring_modulo
        return share_1, share_2

    def secure_relu(self, s1, s2):
        combined = (s1 + s2) % self.ring_modulo
        half_ring = self.ring_modulo // 2
        
        flat_combined = combined.flatten()
        relu_flat = []
        for val in flat_combined:
            signed_val = val - self.ring_modulo if val > half_ring else val
            relu_flat.append(signed_val if signed_val > 0 else 0)
            
        relu_output = np.array(relu_flat, dtype=object).reshape(combined.shape)
        s1_out = np.array([int(np.random.randint(0, 2**30)) % self.ring_modulo for _ in relu_flat], dtype=object).reshape(combined.shape)
        s2_out = (relu_output - s1_out) % self.ring_modulo
        return s1_out, s2_out

    def reconstruct(self, s1, s2):
        combined = (s1 + s2) % self.ring_modulo
        half_ring = self.ring_modulo // 2
        
        flat_combined = combined.flatten()
        rescaled = []
        for val in flat_combined:
            signed_fixed = val - self.ring_modulo if val > half_ring else val
            rescaled.append(float(signed_fixed) / (2 ** self.scale_factor))
            
        return np.array(rescaled).reshape(combined.shape)

def test_athos_end_to_end_pipeline():
    scale = 12
    ring = 2**64
    
    compiler = AthosCompiler(scale, ring)
    backend = MpcExecutionBackend(scale, ring)
    
    raw_inputs = np.array([[0.5, -1.2], [1.5, 2.0]])
    raw_weights = np.array([[2.0, 0.4], [-0.5, 1.1]])
    
    fixed_inputs = compiler.compile_to_fixed_point(raw_inputs)
    fixed_weights = compiler.compile_to_fixed_point(raw_weights)
    
    in_s1, in_s2 = compiler.generate_secret_shares(fixed_inputs)
    w_s1, w_s2 = compiler.generate_secret_shares(fixed_weights)
    
    out_s1, out_s2 = backend.secure_matrix_multiply(in_s1, in_s2, w_s1, w_s2)
    
    combined_matmul = (out_s1 + out_s2) % ring
    half_ring = ring // 2
    
    flat_combined = combined_matmul.flatten()
    corrected_flat = []
    for val in flat_combined:
        signed_val = val - ring if val > half_ring else val
        downscaled = signed_val // (2 ** scale)
        corrected_flat.append(downscaled % ring)
        
    downscaled_matmul = np.array(corrected_flat, dtype=object).reshape(combined_matmul.shape)
    
    out_s1_corrected = np.array([int(np.random.randint(0, 2**30)) % ring for _ in corrected_flat], dtype=object).reshape(combined_matmul.shape)
    out_s2_corrected = (downscaled_matmul - out_s1_corrected) % ring
    
    relu_s1, relu_s2 = backend.secure_relu(out_s1_corrected, out_s2_corrected)
    plaintext_result = backend.reconstruct(relu_s1, relu_s2)
    
    expected_matmul = np.matmul(raw_inputs, raw_weights)
    expected_output = np.where(expected_matmul > 0, expected_matmul, 0)
    
    assert np.allclose(plaintext_result, expected_output, atol=1e-2)
    print("Test Athos Pipeline Passed Successfully.")
    print("Reconstructed MPC Output:\n", plaintext_result)

if __name__ == "__main__":
    test_athos_end_to_end_pipeline()