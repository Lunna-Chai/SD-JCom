
# SD-JCom: Efficient JSON Web Commitment for Selective Disclosure with Proof Non-transferability 

  

A Rust implementation of a **Selective Disclosure JSON Credential** scheme based on **SD-JCom** over the **Ristretto255** implementation of Curve25519 provided by the `curve25519-dalek` library,. The protocol allows a client to commit to a structured JSON document and later selectively disclose chosen attributes with a zero-knowledge proof, while the server signs the commitment using **ES256K** (secp256k1 JWS).

  

---

  

## Table of Contents

  

- [Overview](#overview)

- [Protocol](#protocol)

- [Workspace Structure](#workspace-structure)

- [Dependencies](#dependencies)

- [Build](#build)

- [Running](#running)

- [Benchmarks](#benchmarks)

- [Benchmark Results](#benchmark-results)

  

---

  

## Overview

  

SD-JCom achieves selective disclosure of JSON attributes without revealing the full credential. The commitment scheme is cryptographically binding and the disclosure proofs are zero-knowledge. The approach is compared against SD-JWT and BBS+ in terms of:

  

- **Commitment (issuance) time** vs. number of attributes

- **Proof generation time** vs. number of disclosed attributes

- **Proof size** vs. number of disclosed attributes

- **Verification time** vs. number of disclosed attributes

- **End-to-end latency** across Baseline / LAN / WiFi / WAN network conditions

  

---

  

## Protocol

  

The credential issuance protocol has three phases:

  

```

(server required)

Phase 1 — Client fetches JSON data from server (1 RTT)

Phase 3 — Client submits commitment C + τ;

server verifies C′ == C and signs C (1 RTT)

  

(local CPU only, no network)

Phase 2 — Client samples random scalar z,

computes τ = z·h (h = Ristretto255 base point)

computes C = τ + Σ H(v_i)·g_i

where g_i = Hash-to-Ristretto(DST ‖ path_hash_i)

```

  

The server returns a **JWS ES256K** signature over the commitment C. The client verifies the signature against the server's JWKS public key. JWS/JWKS use secp256k1 (k256) and are fully independent of the Ristretto255 commitment curve.

  

---

  
  

## Workspace Structure

  

| Crate | Role |

|-------|------|

| `json-commit` | Core library: AST parsing, path-tree, commitment, ZK proof |

| `server` | Axum async server: JSON issuance, commitment verification, ES256K signing |

| `client` | Blocking reqwest clients: benchmark runner and interactive CLI |

  

---

  

## Dependencies

  

| Crate | Purpose |

|-------|---------|

| `curve25519-dalek 4` | Ristretto255 group operations, Pedersen commitment |

| `sha2 0.10` | SHA-256 for H(v_i) and SHA-512 for hash-to-curve |

| `rand_core 0.6` | `OsRng` for random scalar z |

| `k256 0.13` | ES256K (secp256k1) signing / verification (JWS) |

| `axum 0.7` + `tokio` | Async HTTP server |

| `reqwest 0.11` (blocking) | HTTP client |

| `base64 0.21` | JWS Base64Url encoding |

| `serde_json` | JSON parsing and serialization |

  

Dev / benchmark only: `sd-jwt-rs`, `pairing_crypto` (BBS+), `ark-bls12-381`, `ark-ec`

  

---

  

## Build

  

```bash

# Build all crates (release)

cargo build --release

  

# Build specific crates

cargo build --release -p server

cargo build --release -p client

```

  

---

  

## Running

  

**Start the server:**

```bash

./target/release/server

# Listening on http://127.0.0.1:8443

```

  

**Interactive client (menu-driven):**

```bash

./target/release/jcommit-client

# Menu:

# 1 — Request JSON data [ONLINE]

# 2 — Compute commitment [OFFLINE]

# 3 — Submit commitment + sign [ONLINE]

# 4 — Benchmark (20 iterations)

# 0 — Exit

```

  

**Benchmark client:**

```bash

./target/release/client --iterations 20

# Output:

# Phase 1 (fetch JSON) : NNNNNN ns (avg)

# Phase 2 (compute commitment): NNNNNN ns (avg)

# Phase 3 (submit + sign) : NNNNNN ns (avg)

# Total Credential Issuance : NNNNNN ns (avg)

```

  

---

  

## Benchmarks

  

### Cryptographic benchmarks (Rust tests)

  

```bash

cd json-commit

  

# Simple JSON end-to-end proof (AST → commitment → ZK proof → verify)

cargo test test_simple_json_path_tree_to_proof --release -- --nocapture

  

# Complex JSON end-to-end proof (asset-proof payload, 100+ attributes)

cargo test test_complex_json_path_tree_to_proof --release -- --nocapture

  

# Commitment issuance time vs. attribute count

cargo test test_our_commit_benchmarks --release -- --nocapture

  

# Proof generation time

cargo test test_proof_gen_benchmarks --release -- --nocapture

  

# Verification time

cargo test test_our_verify_benchmarks --release -- --nocapture

  

# Proof size

cargo test test_proof_size_benchmarks --release -- --nocapture

  

# MSM comparison (Ristretto255 serial vs Pippenger, BLS12-381 serial vs Pippenger)

cargo test test_msm_optimization_comparison --release -- --nocapture

```

  

### Scheme comparison plots (Python)

  

```bash

cd json-commit

  

# Commitment / issuance time: SD-JCom vs SD-JWT vs BBS+

python3 test_benchmarks.py

  

# Proof generation time: SD-JCom vs SD-JWT vs BBS+

python3 test_proof_gen.py

  

# Proof size: SD-JCom vs SD-JWT vs BBS+

python3 test_proof_size.py

  

# Verification time: SD-JCom vs SD-JWT vs BBS+

python3 test_verify_benchmarks.py

```

  

### Network latency benchmark (requires `sudo` + `tc`)

  

```bash

# Ensure the server is running first, then:

cd server

sudo python3 lan_wan_bench.py --iterations 20

```

  

Simulates 6 network scenarios on the loopback interface using Linux `tc netem`:

  

| Scenario | One-way delay | Bandwidth | Packet loss |

|----------|--------------|-----------|-------------|

| Baseline | 0 ms | — | 0% |

| LAN | 0.5 ms | 1 Gbps | 0% |

| WiFi | 5 ms | 100 Mbps | 0% |

| WAN1 | 25 ms | 20 Mbps | 0% |

| WAN2 | 75 ms | 5 Mbps | 0% |

| WAN3| 150 ms | 1 Mbps | 1% |

  

---

  

## Benchmark Results

  

| Scenario | Online (ms) | Offline (ms) | Total (ms) | Online % |

|----------|------------|-------------|-----------|---------|

| Baseline | 5.8 | 5.4 | 11.2 | 51.8% |

| LAN | 9.0 | 5.0 | 14.0 | 64.5% |

| WiFi | 34.8 | 10.3 | 45.1 | 77.2% |

| WAN-near | 121.0 | 13.0 | 134.0 | 90.3% |

| WAN-far | 323.2 | 19.8 | 343.0 | 94.2% |

| WAN-poor | 624.6 | 15.1 | 639.8 | 97.6% |

  

The offline phase (Phase 2, local Pedersen commitment computation) stays below **20 ms** regardless of network conditions, demonstrating that the cryptographic overhead is dominated by network round-trip time in WAN scenarios.