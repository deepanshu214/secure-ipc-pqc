# Quantum-Aware Secure IPC Middleware (Deepanshu's part)

Process A ⇄ secure IPC ⇄ Process B, with the security mode chosen manually: `classical`, `hybrid` or `pq`.

```bash
pip install -r secure_ipc/requirements.txt
python -m secure_ipc.demo        # Phases 1-6: A talks to B in every mode over pipe and Unix socket
python -m secure_ipc.attacks     # Phase 7: attack testing
python -m secure_ipc.benchmark   # Phase 8: performance evaluation
```

## Roadmap → code

| Phase | What | Where |
|---|---|---|
| 1 IPC testbed | two mechanisms: anonymous pipe, Unix domain socket (same `send_bytes/recv_bytes` interface) | `transport.py` |
| 2 Process authentication | each process has signing keys; peers are accepted only if their public key is in the registry (`keys/*.pub.json`); mutual | `crypto.py`, `channel.py` |
| 3 Message security | AES-256-GCM (confidentiality + integrity), sequence number as nonce/AAD, strictly-increasing check (replay) | `channel.py` |
| 4 Classical baseline | X25519 + Ed25519 | `crypto.py` |
| 5 Post-quantum | ML-KEM-768 (FIPS 203) key establishment, ML-DSA-65 (FIPS 204) signatures | `crypto.py` |
| 6 Hybrid | both together: secrets concatenated into HKDF, both signatures required | `crypto.py` |
| 7 Attack testing | 7 attacks × 3 modes, detected? + detection time | `attacks.py` |
| 8 Evaluation | primitives, handshake time/bytes, latency, throughput, CPU, memory | `benchmark.py` |

## How it works

```
A → B : hello  [name, mode, nonce_a, kex public]  + A's signature
B → A : reply  [name, nonce_b, kex reply]         + B's signature over hello+reply
key   = HKDF(shared secret, nonce_a + nonce_b)
frame = seq(8 B) + AES-GCM(key, nonce = direction+seq, aad = seq)     → 24 B overhead
```

## Notes (for the viva)

- Standard algorithms only (X25519, Ed25519, ML-KEM, ML-DSA, AES-GCM, HKDF) – nothing novel claimed.
- The three modes differ in **authentication + key establishment**; the per-message cipher is AES-256-GCM in all of them (AES-256 is already considered quantum-resistant), so per-message cost is the same.
- ML-KEM/ML-DSA come from `kyber-py` / `dilithium-py`: pure Python, educational, not constant-time. Their timings are far slower than C implementations (e.g. liboqs), so compare modes *relatively*, not as absolute PQC speed.
- "Process identity" = possession of a registered private key, not OS-level (PID/UID) identity.
- Memory is peak Python heap during one handshake (both ends); CPU is Process A's CPU time.
- `keys/` holds private keys and is git-ignored; it is auto-generated on first run.
