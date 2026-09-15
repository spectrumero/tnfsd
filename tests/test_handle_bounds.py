#!/usr/bin/env python3
"""Regression test: out-of-range dir/file handles must be rejected.

The handle checks used '> MAX_DHND_PER_CONN' / '> MAX_FD_PER_CONN' where they
needed '>='.  Handle 8 indexed one past dhandles[8] (onto Session.root) and
handle 16 one past fd[16] (onto atari_fd[0]) -- a client-triggerable
out-of-bounds read, and an out-of-bounds write in CLOSEDIR.
"""

import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOST = "127.0.0.1"
MAX_DHND_PER_CONN = 8
MAX_FD_PER_CONN = 16

TNFS_MOUNT = 0x00
TNFS_READDIR = 0x11
TNFS_CLOSEDIR = 0x12
TNFS_SEEKDIR = 0x16
TNFS_READDIRX = 0x18
TNFS_CLOSEFILE = 0x23
TNFS_EBADF = 0x06
TNFS_EBADFD = 0x1C
PROTOVERSION = b"\x03\x01"


def find_available_port():
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


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


def exchange(client, address, sid, seqno, command, payload=b""):
    client.sendto(sid.to_bytes(2, "little") + bytes((seqno, command)) + payload, address)
    client.settimeout(5)
    response, _ = client.recvfrom(532)
    if len(response) < 5:
        raise AssertionError(f"short response to 0x{command:02x}: {response!r}")
    return response[4], response[5:]


def main():
    default_server = Path(__file__).resolve().parents[1] / "bin" / "tnfsd"
    server_path = Path(sys.argv[1] if len(sys.argv) > 1 else default_server).resolve()
    if not server_path.is_file():
        raise FileNotFoundError(f"tnfsd binary not found: {server_path}")

    port = find_available_port()
    address = (HOST, port)
    failures = []

    with tempfile.TemporaryDirectory(prefix="tnfsd-bounds-") as root_dir:
        server = subprocess.Popen(
            (str(server_path), "-p", str(port), root_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                wait_until_ready(server, address)
                status, body = exchange(
                    client, address, 0, 1, TNFS_MOUNT,
                    PROTOVERSION + b"/\x00" + b"\x00" + b"\x00",
                )
                if status != 0:
                    raise AssertionError(f"MOUNT failed with status 0x{status:02x}")
                # re-mount to read back the session id
                client.sendto(
                    (0).to_bytes(2, "little") + bytes((2, TNFS_MOUNT))
                    + PROTOVERSION + b"/\x00" + b"\x00" + b"\x00",
                    address,
                )
                client.settimeout(5)
                resp, _ = client.recvfrom(532)
                sid = int.from_bytes(resp[0:2], "little")

                # Directory commands answer EBADF; the file path uses EBADFD.
                cases = [
                    ("CLOSEDIR", TNFS_CLOSEDIR, bytes((MAX_DHND_PER_CONN,)), TNFS_EBADF),
                    ("READDIR", TNFS_READDIR, bytes((MAX_DHND_PER_CONN,)), TNFS_EBADF),
                    ("SEEKDIR", TNFS_SEEKDIR, bytes((MAX_DHND_PER_CONN, 0, 0, 0, 0)), TNFS_EBADF),
                    ("READDIRX", TNFS_READDIRX, bytes((MAX_DHND_PER_CONN, 1)), TNFS_EBADF),
                    ("CLOSEFILE", TNFS_CLOSEFILE, bytes((MAX_FD_PER_CONN,)), TNFS_EBADFD),
                ]

                seqno = 3
                for name, command, payload, expected in cases:
                    try:
                        status, _ = exchange(client, address, sid, seqno, command, payload)
                    except socket.timeout:
                        failures.append(f"{name}: no reply (server may have crashed)")
                        break
                    if status != expected:
                        failures.append(
                            f"{name} with handle {payload[0]}: expected "
                            f"0x{expected:02x}, got 0x{status:02x}"
                        )
                    else:
                        print(f"  {name} handle {payload[0]}: rejected 0x{status:02x} (ok)")
                    seqno = (seqno + 1) & 0xFF

                if server.poll() is not None:
                    failures.append(f"server died (status {server.returncode})")
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("PASS: out-of-range handles rejected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
