"""Phase 8: performance evaluation. Run: python -m secure_ipc.benchmark

1. Primitive timings (key establishment, signatures, AES-GCM encrypt/decrypt)
2. Per mode x transport: handshake time/bytes, round-trip latency, throughput, CPU, memory
"""
import os
import statistics
import time
import tracemalloc

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

from .channel import accept, connect
from .crypto import MODES, ensure_keys, load_identity, sign, verify, load_public
from .transport import TRANSPORTS, local_pair, spawn_peer

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
SMALL, LARGE = 1024, 64 * 1024
N_SMALL, N_LARGE = 300, 100


def median_ms(fn, runs=20):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times) * 1000


def primitives():
    ident, pub = load_identity("processA", KEY_DIR), load_public("processA", KEY_DIR)
    msg = os.urandom(256)
    ed_sig, dsa_sig = sign(ident, "classical", msg), sign(ident, "pq", msg)
    ek, dk = ML_KEM_768.keygen()
    _, ct = ML_KEM_768.encaps(ek)
    peer = x25519.X25519PrivateKey.generate().public_key()
    key, data = AESGCM(os.urandom(32)), os.urandom(SMALL)
    nonce = os.urandom(12)
    sealed = key.encrypt(nonce, data, None)
    rows = [
        ("X25519 keygen + DH", lambda: x25519.X25519PrivateKey.generate().exchange(peer)),
        ("ML-KEM-768 keygen", ML_KEM_768.keygen),
        ("ML-KEM-768 encaps", lambda: ML_KEM_768.encaps(ek)),
        ("ML-KEM-768 decaps", lambda: ML_KEM_768.decaps(dk, ct)),
        ("Ed25519 sign", lambda: sign(ident, "classical", msg)),
        ("Ed25519 verify", lambda: verify(pub, "classical", msg, ed_sig)),
        ("ML-DSA-65 sign", lambda: sign(ident, "pq", msg)),
        ("ML-DSA-65 verify", lambda: verify(pub, "pq", msg, dsa_sig)),
        ("AES-256-GCM encrypt 1 KB", lambda: key.encrypt(nonce, data, None)),
        ("AES-256-GCM decrypt 1 KB", lambda: key.decrypt(nonce, sealed, None)),
    ]
    print("| Operation | Median time (ms) |\n|---|---|")
    for name, fn in rows:
        print(f"| {name} | {median_ms(fn):.3f} |")
    print(f"\nSizes (bytes): X25519 public {32}, ML-KEM-768 public key {len(ek)} / ciphertext {len(ct)}, "
          f"Ed25519 signature {len(ed_sig)}, ML-DSA-65 signature {len(dsa_sig)}")


class Counting:
    """Connection wrapper that counts bytes sent and received."""
    def __init__(self, conn):
        self.conn, self.bytes = conn, 0

    def send_bytes(self, data):
        self.bytes += len(data)
        self.conn.send_bytes(data)

    def recv_bytes(self):
        data = self.conn.recv_bytes()
        self.bytes += len(data)
        return data

    def close(self):
        self.conn.close()


def echo_peer(conn, mode, key_dir):
    conn.send_bytes(b"ready")  # lets the benchmark exclude process start-up from the handshake time
    chan, _ = accept(conn, load_identity("processB", key_dir), key_dir, mode)
    while True:
        msg = chan.recv()
        if msg == b"quit":
            break
        chan.send(msg)


def handshake_memory_kb(mode):
    tracemalloc.start()
    local_pair(mode, KEY_DIR)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return peak / 1024


def bench(mode, transport):
    proc, raw = spawn_peer(transport, echo_peer, mode, KEY_DIR)
    raw.recv_bytes()
    conn = Counting(raw)
    cpu_start = time.process_time()

    start = time.perf_counter()
    chan = connect(conn, load_identity("processA", KEY_DIR), KEY_DIR, mode, "processB")
    handshake_ms = (time.perf_counter() - start) * 1000
    handshake_bytes = conn.bytes

    payload = os.urandom(SMALL)
    start = time.perf_counter()
    for _ in range(N_SMALL):
        chan.send(payload)
        chan.recv()
    rtt_ms = (time.perf_counter() - start) * 1000 / N_SMALL

    payload = os.urandom(LARGE)
    start = time.perf_counter()
    for _ in range(N_LARGE):
        chan.send(payload)
        chan.recv()
    throughput = N_LARGE * LARGE / (time.perf_counter() - start) / 1e6

    cpu_ms = (time.process_time() - cpu_start) * 1000
    chan.send(b"quit")
    proc.join()
    return handshake_ms, handshake_bytes, rtt_ms, throughput, cpu_ms


def main():
    ensure_keys(KEY_DIR)
    print("## Primitives\n")
    primitives()
    print("\n## IPC (per mode and transport)\n")
    print(f"Round-trip = {SMALL} B message sent and echoed back; throughput = {LARGE // 1024} KB messages echoed; "
          "CPU = Process A CPU time for handshake + all messages; memory = peak Python heap during one handshake (both ends).\n")
    print("| Transport | Mode | Handshake (ms) | Handshake bytes | Round-trip (ms) | Throughput (MB/s) | CPU A (ms) | Handshake mem (KB) |")
    print("|---|---|---|---|---|---|---|---|")
    for transport in TRANSPORTS:
        for mode in MODES:
            hs, hs_bytes, rtt, tp, cpu = bench(mode, transport)
            print(f"| {transport} | {mode} | {hs:.1f} | {hs_bytes} | {rtt:.3f} | {tp:.1f} | {cpu:.0f} | {handshake_memory_kb(mode):.0f} |")
    print("\nPer-message size overhead (all modes): 8 B sequence number + 16 B GCM tag = 24 B.")


if __name__ == "__main__":
    main()
