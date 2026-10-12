"""Crypto building blocks for the three security modes.

classical : X25519 key exchange   + Ed25519 signatures
pq        : ML-KEM-768 (FIPS 203) + ML-DSA-65 signatures (FIPS 204)
hybrid    : both of the above together (secrets are concatenated, both signatures required)

All modes protect the actual messages with AES-256-GCM (see channel.py).
"""
import json
import os
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

MODES = ("classical", "hybrid", "pq")
ED_SIG_LEN = 64
X_PUB_LEN = 32

_RAW_PUB = dict(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)
_RAW_PRIV = dict(encoding=ser.Encoding.Raw, format=ser.PrivateFormat.Raw,
                 encryption_algorithm=ser.NoEncryption())


def _x_pub(private_key):
    return private_key.public_key().public_bytes(**_RAW_PUB)


# ---------- length-prefixed packing for handshake messages ----------

def pack(*parts):
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def unpack(data):
    parts, i = [], 0
    while i < len(data):
        n = int.from_bytes(data[i:i + 4], "big")
        if i + 4 + n > len(data):
            raise ValueError("truncated message")
        parts.append(data[i + 4:i + 4 + n])
        i += 4 + n
    return parts


# ---------- process identities (long-term signing keys) ----------

def create_identity(name, key_dir):
    """Make signing keys for a process. Public half goes in <name>.pub.json (the registry)."""
    os.makedirs(key_dir, exist_ok=True)
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    dsa_pk, dsa_sk = ML_DSA_65.keygen()
    pub = {"ed_pk": ed_sk.public_key().public_bytes(**_RAW_PUB).hex(), "dsa_pk": dsa_pk.hex()}
    priv = {"name": name, **pub, "ed_sk": ed_sk.private_bytes(**_RAW_PRIV).hex(), "dsa_sk": dsa_sk.hex()}
    with open(os.path.join(key_dir, f"{name}.pub.json"), "w") as f:
        json.dump(pub, f)
    key_path = os.path.join(key_dir, f"{name}.key.json")
    with open(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(priv, f)


def _read(path):
    with open(path) as f:
        return {k: bytes.fromhex(v) if k != "name" else v for k, v in json.load(f).items()}


def load_identity(name, key_dir):
    return _read(os.path.join(key_dir, f"{name}.key.json"))


def load_public(name, key_dir):
    """Public keys of an *authorized* process, or None if it is not registered."""
    if not re.fullmatch(r"\w+", name):
        return None
    path = os.path.join(key_dir, f"{name}.pub.json")
    return _read(path) if os.path.exists(path) else None


def ensure_keys(key_dir):
    for name in ("processA", "processB"):
        if not os.path.exists(os.path.join(key_dir, f"{name}.key.json")):
            create_identity(name, key_dir)


# ---------- signatures ----------

def sign(identity, mode, msg):
    sig = b""
    if mode != "pq":
        sig += ed25519.Ed25519PrivateKey.from_private_bytes(identity["ed_sk"]).sign(msg)
    if mode != "classical":
        sig += ML_DSA_65.sign(identity["dsa_sk"], msg)
    return sig


def verify(public, mode, msg, sig):
    try:
        if mode != "pq":
            ed25519.Ed25519PublicKey.from_public_bytes(public["ed_pk"]).verify(sig[:ED_SIG_LEN], msg)
            sig = sig[ED_SIG_LEN:]
        if mode != "classical":
            return ML_DSA_65.verify(public["dsa_pk"], msg, sig)
        return True
    except Exception:  # bad signature or malformed input from an untrusted peer
        return False


# ---------- key exchange ----------

def kex_start(mode):
    """Initiator: returns (private state, public blob to send)."""
    state, blob = {}, b""
    if mode != "pq":
        state["x"] = x25519.X25519PrivateKey.generate()
        blob += _x_pub(state["x"])
    if mode != "classical":
        ek, state["dk"] = ML_KEM_768.keygen()
        blob += ek
    return state, blob


def kex_respond(mode, blob):
    """Responder: returns (reply blob, shared secret)."""
    reply, secret = b"", b""
    if mode != "pq":
        x = x25519.X25519PrivateKey.generate()
        secret += x.exchange(x25519.X25519PublicKey.from_public_bytes(blob[:X_PUB_LEN]))
        reply += _x_pub(x)
        blob = blob[X_PUB_LEN:]
    if mode != "classical":
        shared, ct = ML_KEM_768.encaps(blob)
        secret += shared
        reply += ct
    return reply, secret


def kex_finish(mode, state, reply):
    """Initiator: shared secret from the responder's reply."""
    secret = b""
    if mode != "pq":
        secret += state["x"].exchange(x25519.X25519PublicKey.from_public_bytes(reply[:X_PUB_LEN]))
        reply = reply[X_PUB_LEN:]
    if mode != "classical":
        secret += ML_KEM_768.decaps(state["dk"], reply)
    return secret


def derive_key(secret, nonce_a, nonce_b, mode):
    return HKDF(hashes.SHA256(), 32, salt=nonce_a + nonce_b,
                info=b"secure-ipc " + mode.encode()).derive(secret)
