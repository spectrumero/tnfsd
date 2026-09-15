#!/usr/bin/env python3
"""Regression test: OPENDIR/CLOSEDIR must not leak directory descriptors.

tnfs_closedir() used to clear the handle's 'open' flag without calling
closedir(), and every reclaim path keys off 'loaded' -- which plain OPENDIR
never sets.  Each OPENDIR therefore leaked one fd for the life of the process,
reaching the default 1024 soft limit in roughly a day of normal browsing.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOST = "127.0.0.1"
ANY_ADDRESS = "0.0.0.0"
CYCLES = 300

TNFS_MOUNT = 0x00
TNFS_OPENDIR = 0x10
TNFS_CLOSEDIR = 0x12
PROTOVERSION = b"\x03\x01"


def find_available_port():
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.bind((ANY_ADDRESS, 0))
            port = tcp_socket.getsockname()[1]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind((ANY_ADDRESS, port))
            except OSError:
                continue
            return port
    raise RuntimeError("could not find a port available for both TCP and UDP")


def wait_until_ready(server, address):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError(f"tnfsd exited during startup with status {server.returncode}")
        try:
            with socket.create_connection(address, timeout=0.1):
                pass
            return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("tnfsd did not begin accepting connections")


def request(client, address, sid, seqno, command, payload=b""):
    client.sendto(
        sid.to_bytes(2, "little") + bytes((seqno, command)) + payload, address
    )
    client.settimeout(5)
    response, _ = client.recvfrom(532)
    if len(response) < 5:
        raise AssertionError(f"short response to command 0x{command:02x}: {response!r}")
    if response[2] != seqno or response[3] != command:
        raise AssertionError(
            f"mismatched reply: want seq={seqno} cmd=0x{command:02x}, "
            f"got seq={response[2]} cmd=0x{response[3]:02x}"
        )
    status = response[4]
    if status != 0:
        raise AssertionError(f"command 0x{command:02x} failed with status 0x{status:02x}")
    return int.from_bytes(response[0:2], "little"), response[5:]


def open_fd_count(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def main():
    if not Path("/proc/self/fd").is_dir():
        print("SKIP: /proc is required to count open descriptors")
        return 0

    default_server = Path(__file__).resolve().parents[1] / "bin" / "tnfsd"
    server_path = Path(sys.argv[1] if len(sys.argv) > 1 else default_server).resolve()
    if not server_path.is_file():
        raise FileNotFoundError(f"tnfsd binary not found: {server_path}")

    port = find_available_port()
    address = (HOST, port)

    with tempfile.TemporaryDirectory(prefix="tnfsd-dirleak-") as root_dir:
        os.mkdir(os.path.join(root_dir, "subdir"))
        server = subprocess.Popen(
            (str(server_path), "-p", str(port), root_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                wait_until_ready(server, address)

                sid, _ = request(
                    client, address, 0, 1, TNFS_MOUNT,
                    PROTOVERSION + b"/\x00" + b"\x00" + b"\x00",
                )

                seqno = 2
                # Settle first: the mount itself touches descriptors.
                for _ in range(10):
                    _, body = request(client, address, sid, seqno, TNFS_OPENDIR, b"/subdir\x00")
                    seqno = (seqno + 1) & 0xFF
                    request(client, address, sid, seqno, TNFS_CLOSEDIR, bytes((body[0],)))
                    seqno = (seqno + 1) & 0xFF

                baseline = open_fd_count(server.pid)

                for _ in range(CYCLES):
                    _, body = request(client, address, sid, seqno, TNFS_OPENDIR, b"/subdir\x00")
                    seqno = (seqno + 1) & 0xFF
                    request(client, address, sid, seqno, TNFS_CLOSEDIR, bytes((body[0],)))
                    seqno = (seqno + 1) & 0xFF

                final = open_fd_count(server.pid)
                growth = final - baseline
                print(
                    f"open fds: baseline={baseline} after {CYCLES} "
                    f"OPENDIR/CLOSEDIR cycles={final} (growth={growth})"
                )
                if growth > 1:
                    raise AssertionError(
                        f"leaked {growth} descriptors over {CYCLES} cycles"
                    )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)

    print("PASS: no descriptor growth")
    return 0


if __name__ == "__main__":
    sys.exit(main())
