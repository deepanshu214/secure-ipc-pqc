"""Process A -> secure IPC -> Process B, for every transport and every manually chosen mode.

Run from the project root:  python -m secure_ipc.demo
"""
import os

from .channel import accept, connect
from .crypto import MODES, ensure_keys, load_identity
from .transport import TRANSPORTS, spawn_peer

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")


def process_b(conn, mode, key_dir):
    chan, peer = accept(conn, load_identity("processB", key_dir), key_dir, mode)
    msg = chan.recv()
    print(f"    B: authenticated '{peer}', received {msg!r}")
    chan.send(b"ACK " + msg)


def main():
    ensure_keys(KEY_DIR)
    for transport in TRANSPORTS:
        for mode in MODES:
            print(f"[{transport} / {mode}]")
            proc, conn = spawn_peer(transport, process_b, mode, KEY_DIR)
            chan = connect(conn, load_identity("processA", KEY_DIR), KEY_DIR, mode, "processB")
            chan.send(b"Emergency detected")
            print(f"    A: got reply {chan.recv()!r}")
            proc.join()


if __name__ == "__main__":
    main()
