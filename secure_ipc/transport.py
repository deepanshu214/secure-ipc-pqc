"""Two IPC mechanisms behind the same send_bytes/recv_bytes interface.

pipe   : multiprocessing.Pipe  (anonymous pipe)
socket : Unix domain socket    (multiprocessing.connection Listener/Client)
"""
import os
import tempfile
from multiprocessing import Pipe, Process
from multiprocessing.connection import Client, Listener
from threading import Thread

from .channel import accept, connect
from .crypto import load_identity

TRANSPORTS = ("pipe", "socket")


def _run_on_socket(path, target, args):
    target(Client(path, family="AF_UNIX"), *args)


def spawn_peer(kind, target, *args):
    """Start target(conn, *args) in a new process. Returns (process, our end of the connection)."""
    if kind == "pipe":
        ours, theirs = Pipe()
        proc = Process(target=target, args=(theirs, *args))
        proc.start()
        theirs.close()
        return proc, ours
    path = os.path.join(tempfile.mkdtemp(), "ipc.sock")
    with Listener(path, family="AF_UNIX") as listener:
        proc = Process(target=_run_on_socket, args=(path, target, args))
        proc.start()
        return proc, listener.accept()


def local_pair(mode, key_dir):
    """Both ends in this process (B on a thread). Returns (channel A, channel B). Used by tests/benchmarks."""
    a_conn, b_conn = Pipe()
    result = {}

    def run_b():
        result["b"] = accept(b_conn, load_identity("processB", key_dir), key_dir, mode)[0]

    thread = Thread(target=run_b)
    thread.start()
    chan_a = connect(a_conn, load_identity("processA", key_dir), key_dir, mode, "processB")
    thread.join()
    return chan_a, result["b"]
