"""Authenticated handshake + encrypted channel on top of any connection with send_bytes/recv_bytes.

Handshake (Process A = initiator, Process B = responder, both authenticate each other):
  A -> B : hello  = [name, mode, nonce_a, key-exchange public] + A's signature
  B -> A : reply  = [name, nonce_b, key-exchange reply]        + B's signature over (hello body + reply body)
Each side looks the other up in the registry of authorized processes (public keys in key_dir).
Session key = HKDF(shared secret, nonces).

Messages: AES-256-GCM  -> confidentiality + integrity.
Sequence number is the GCM nonce and AAD     -> tampering with it fails the tag.
Receiver accepts only strictly increasing seq -> replay protection.
"""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import (derive_key, kex_finish, kex_respond, kex_start, load_public, pack, sign,
                     unpack, verify)


class AuthError(Exception):
    """Peer is unknown, signed with the wrong key, or the handshake is malformed."""


class IntegrityError(Exception):
    """Message was modified or corrupted."""


class ReplayError(Exception):
    """Message sequence number was already seen."""


class SecureChannel:
    def __init__(self, conn, key, initiator):
        self.conn = conn
        self.aead = AESGCM(key)
        self.seq = 0        # last number we sent
        self.last_seq = 0   # last number we accepted
        self.send_dir, self.recv_dir = (b"I2R\0", b"R2I\0") if initiator else (b"R2I\0", b"I2R\0")

    def seal(self, data):
        """seq (8 bytes) + AES-GCM ciphertext (+16 byte tag)."""
        self.seq += 1
        seq = self.seq.to_bytes(8, "big")
        return seq + self.aead.encrypt(self.send_dir + seq, data, seq)

    def open(self, frame):
        if len(frame) < 8 + 16:
            raise IntegrityError("frame too short")
        seq = frame[:8]
        try:
            data = self.aead.decrypt(self.recv_dir + seq, frame[8:], seq)
        except InvalidTag:
            raise IntegrityError("authentication tag mismatch") from None
        n = int.from_bytes(seq, "big")
        if n <= self.last_seq:
            raise ReplayError(f"sequence {n} already seen (last {self.last_seq})")
        self.last_seq = n
        return data

    def send(self, data):
        self.conn.send_bytes(self.seal(data))

    def recv(self):
        return self.open(self.conn.recv_bytes())

    def close(self):
        self.conn.close()


def connect(conn, me, key_dir, mode, peer_name):
    """Initiator side. `me` is this process's identity (crypto.load_identity)."""
    try:
        return _connect(conn, me, key_dir, mode, peer_name)
    except Exception as e:
        conn.close()
        raise (e if isinstance(e, AuthError) else AuthError(f"handshake failed: {e!r}"))


def _connect(conn, me, key_dir, mode, peer_name):
    state, kex = kex_start(mode)
    nonce_a = os.urandom(16)
    body = pack(me["name"].encode(), mode.encode(), nonce_a, kex)
    conn.send_bytes(pack(body, sign(me, mode, body)))

    r_body, r_sig = unpack(conn.recv_bytes())
    name_b, nonce_b, kex_reply = unpack(r_body)
    peer = load_public(name_b.decode(), key_dir)
    if name_b.decode() != peer_name or peer is None:
        raise AuthError(f"unexpected peer {name_b!r}")
    if not verify(peer, mode, body + r_body, r_sig):
        raise AuthError("invalid signature from responder")

    key = derive_key(kex_finish(mode, state, kex_reply), nonce_a, nonce_b, mode)
    return SecureChannel(conn, key, initiator=True)


def accept(conn, me, key_dir, mode):
    """Responder side. Returns (channel, authenticated peer name)."""
    try:
        return _accept(conn, me, key_dir, mode)
    except Exception as e:
        conn.close()
        raise (e if isinstance(e, AuthError) else AuthError(f"handshake failed: {e!r}"))


def _accept(conn, me, key_dir, mode):
    body, sig = unpack(conn.recv_bytes())
    name_a, mode_a, nonce_a, kex = unpack(body)
    peer = load_public(name_a.decode(), key_dir)
    if peer is None:
        raise AuthError(f"process {name_a!r} is not authorized")
    if mode_a.decode() != mode:
        raise AuthError("mode mismatch")
    if not verify(peer, mode, body, sig):
        raise AuthError(f"invalid signature from {name_a!r}")

    nonce_b = os.urandom(16)
    kex_reply, secret = kex_respond(mode, kex)
    r_body = pack(me["name"].encode(), nonce_b, kex_reply)
    conn.send_bytes(pack(r_body, sign(me, mode, body + r_body)))

    key = derive_key(secret, nonce_a, nonce_b, mode)
    return SecureChannel(conn, key, initiator=False), name_a.decode()
