# Post-Quantum ZKPs & Cryptographic Vaults

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Cryptography: Post-Quantum](https://img.shields.io/badge/Crypto-CRYSTALS--Kyber%20%7C%20Poseidon%20%7C%20PIANIST-purple.svg)](#cryptographic-primitives)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM%20%7C%20Argon2id-blue.svg)](#security-architecture)

This project is a novel cryptographic research library for **ZKP**, **PQC**, and **Threshold Cryptography**, for privacy-preserving verifiable computations and secure decentralized password vaults.

---

## Table of Contents

- [Overview](#-overview)
- [Cryptographic Primitives](#-cryptographic-primitives)
- [Modules & Architecture](#-modules--architecture)
- [Vault v2 Specifications](#-vault-v2-specifications)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage & Running Scripts](#usage--running-scripts)
- [Project Structure](#-project-structure)
- [Roadmap & Research Directions](#-roadmap--research-directions)
- [Contributing](#-contributing)
- [License](#-license)
---

## Summary

This repository shows the actual application of:
1. **Zero-Knowledge Proof Systems** to create succinct, non-interactive verifiable credentials.
2. **Post-Quantum Cryptography using Lattice Structures** that will resist quantum cryptanalysis.
3. **Threshold Secret Sharing & Fault-Tolerant Distributed Vaults**.

---

## Cryptographic Protocols

| Protocol / Primitive | Implementation file | Description |
| :--- | :--- | :--- |
| **Poseidon Hash Function** | `poseidon.py` | ZK-friendly cryptographic sponge construction over the **BN254** scalar field |
| **PIANIST / ATHOS** | `PIANIST.py`, `ATHOS.py` | Multi-party zero-knowledge proof protocol for proving systems and additive secret sharing |
| **CRYSTALS-Kyber** | `kyber.py` | Post-quantum lattice-based Key Encapsulation Mechanism (KEM) |
| **LaZer** | `LaZer.py` | Lattice-based Zero-Knowledge protocol |
| **Hybrid schemes** | `hybrid.py`, `hybrid2.py` | Hybrid classical and post-quantum threshold protocols |
| **Cryptographic Vault v2** | `vault_v2.py` | Distributed threshold password vault with AES-256-GCM and Argon2id |

---

## Vault v2 Architecture

The following depicts `vault_v2.py`, a well-secured, privacy-enhancing threshold password manager architecture:

```
[Master Secret]
       │
       ▼  (Argon2id Key Derivation)
[Derived Key] ────► [AES-256-GCM Encryption] ───► [Ciphertext Stored]
       │
       ▼  (Shamir (3,5) Threshold Sharing over Mersenne Prime Field)
  [Share 1]  [Share 2]  [Share 3]  [Share 4]  [Share 5]
       │          │          │
       └──────────┼──────────┘ (Any 3 shares reconstruct secret)
                  ▼
          [Poseidon ZKP Verification]
```

- **AEAD Encryption**: Authentication encryption through `AES-256-GCM`.
- **Memory-Hard KDF**: `Argon2id` which is secure against brute-forcing attacks using ASICs/GPUs.
- **Threshold Scheme**: $(k, n) = (3, 5)$ Shamir Secret Sharing with failure tolerance capability.
- **BN254 Scalar Field**: $p = 21888242871839275222246405745257275088548364400416034343698204186575808495617$.

---

## Project Structure

```text
Zero-knowledge--proofing/
├── ATHOS.py          # ATHOS additive secret sharing & proof construction framework 
├── LaZer.py          # Lattice-based zero-knowledge proofs routines
├── PIANIST.py        # PIANIST threshold zero-knowledge verification protocol
├── poseidon.py       # Poseidon permutation and hash on BN254 optimized
├── kyber.py          # CRYSTALS-Kyber post-quantum KEM implementation 
├── hybrid.py         # Classical and post-quantum hybrid zero-knowledge proving 
├── hybrid2.py        # Extended hybrid threshold protocols 
├── vault_v2.py       # Fault-tolerant distributed password vault demonstration 
├── LICENSE           # MIT license
└── README.md         # Project documentation
```

---

## Setup

### Requirements

- **Python version 3.9+**
- Virtual environment is advised (using `venv` or `conda`)

### Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/Sabareesh-06/Zero-knowledge--proofing.git
    cd Zero-knowledge--proofing
    ```

2. **Dependencies installation:**
    ```bash
    pip install argon2-cffi cryptography
    ```
    
### Usage & Executing Scripts

- **Execute the Cryptographic Password Vault (version 2):**
  ```bash
  python vault_v2.py
  ```

- **Poseidon Hash Function using BN254:**
  ```bash
  python poseidon.py
  ```

- **Post Quantum Kyber Key Encapsulation Mechanism:**
  ```bash
  python kyber.py
  ```

- **Hybrid Proof Execution:**
  ```bash
  python hybrid.py
  python hybrid2.py
  ```

---

## Roadmap & Research Directions

- [ ] Snarkjs / Circom interoperability support for Poseidon hash constraints.
- [ ] Dilithium / SPHINCS+ post-quantum digital signatures verification.
- [ ] Add a full benchmarking framework to compare performance of Poseidon vs SHA-256 in circuits in terms of gas/cycle costs.
- [ ] CLI interface for recovering secret shares.

---

## Contributing

Contributions and research ideas are encouraged. Feel free to open an issue or pull request.

---

## License

Licensed under the **MIT License**. See the file [`LICENSE`](LICENSE).
