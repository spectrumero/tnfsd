#!/usr/bin/env python3
"""Regression test for TNFS root confinement (directory traversal).

A TNFS client must never be able to escape the served root directory. Two
independent defenses enforce this in the daemon:

  * File operations (STAT/OPEN/UNLINK/RENAME/MKDIR/RMDIR) go through
    tnfs_valid_filename(), which rejects any path containing "..".
  * Directory listings (OPENDIR) have no ".." check of their own and rely
    entirely on validate_path(), which resolves the path with realpath()
    and silently clamps it back to the root when it points outside.

This test plants a secret file *outside* the served root and confirms a
client cannot reach it via either path. It speaks just enough of the TNFS
UDP protocol (MOUNT / OPENDIR / READDIR / STAT) to do so.

Note: confinement via validate_path() is compiled in on the default
(ENABLE_CHROOT) Unix build. A binary built with ENABLE_CHROOT=no
deliberately allows escaping the root (to support symlinks), so this test
is expected to run against the default build, as CI does.
"""

import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HOST = "127.0.0.1"
ANY_ADDRESS = "0.0.0.0"

# Command bytes
TNFS_MOUNT = 0x00
TNFS_OPENDIR = 0x10
TNFS_READDIR = 0x11
TNFS_STAT = 0x24

# Status bytes
TNFS_SUCCESS = 0x00
TNFS_EINVAL = 0x0E
TNFS_EOF = 0x21

INSIDE_NAME = "inside.txt"
SECRET_NAME = "secret.txt"


def find_available_port():
    """Find a port currently available for both TCP and UDP."""
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.bind((ANY_ADDRESS, 0))
            port = tcp_socket.getsockname()[1]

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
                    udp_socket.bind((ANY_ADDRESS, port))
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


def stop_server(server):
    if server.poll() is not None:
        return

    server.send_signal(signal.SIGINT)
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)


class TnfsClient:
    """A minimal TNFS-over-UDP client: just enough to test confinement."""

    def __init__(self, address):
        self._address = address
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(0.5)
        self._sid = 0x0000
        self._seqno = 0

    def close(self):
        self._sock.close()

    def _next_seqno(self):
        self._seqno = (self._seqno + 1) & 0xFF
        return self._seqno

    def _request(self, cmd, payload=b"", sid=None):
        """Send one request and return (status, data_after_status, header_sid).

        Retries on timeout and ignores datagrams whose sequence number does
        not match the request (per the protocol, those are stale/retries).
        """
        seqno = self._next_seqno()
        sid = self._sid if sid is None else sid
        packet = struct.pack("<HBB", sid, seqno, cmd) + payload

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self._sock.sendto(packet, self._address)
            try:
                response = self._sock.recv(1024)
            except socket.timeout:
                continue
            if len(response) < 5:
                continue
            resp_sid, resp_seqno, resp_cmd = struct.unpack_from("<HBB", response, 0)
            if resp_seqno != seqno or resp_cmd != cmd:
                continue
            status = response[4]
            return status, response[5:], resp_sid

        raise TimeoutError(f"no response to command 0x{cmd:02x}")

    def mount(self, mountpoint="/"):
        # payload: 16-bit version LE, then NUL-terminated mountpoint/user/pass
        payload = struct.pack("<H", 0x0100) + mountpoint.encode() + b"\x00" + b"\x00" + b"\x00"
        status, _, header_sid = self._request(TNFS_MOUNT, payload, sid=0x0000)
        if status != TNFS_SUCCESS:
            raise RuntimeError(f"MOUNT failed with status 0x{status:02x}")
        self._sid = header_sid
        return header_sid

    def opendir(self, path):
        status, data, _ = self._request(TNFS_OPENDIR, path.encode() + b"\x00")
        handle = data[0] if (status == TNFS_SUCCESS and data) else None
        return status, handle

    def readdir_names(self, handle):
        """Read every entry from an open directory handle."""
        names = []
        for _ in range(1000):  # generous guard against a runaway handle
            status, data, _ = self._request(TNFS_READDIR, bytes((handle,)))
            if status == TNFS_EOF:
                break
            if status != TNFS_SUCCESS:
                raise RuntimeError(f"READDIR returned status 0x{status:02x}")
            names.append(data.split(b"\x00", 1)[0].decode(errors="replace"))
        return names

    def stat(self, path):
        status, _, _ = self._request(TNFS_STAT, path.encode() + b"\x00")
        return status

    def list_dir(self, path):
        status, handle = self.opendir(path)
        if status != TNFS_SUCCESS or handle is None:
            raise RuntimeError(f"OPENDIR {path!r} failed with status 0x{status:02x}")
        return self.readdir_names(handle)


def run_checks(client):
    # Positive control: the root is listable and the inside file is visible.
    root_entries = client.list_dir("/")
    if INSIDE_NAME not in root_entries:
        raise AssertionError(
            f"expected {INSIDE_NAME!r} in root listing, got {sorted(root_entries)}"
        )
    if SECRET_NAME in root_entries:
        raise AssertionError(
            f"{SECRET_NAME!r} leaked into the root listing itself: {sorted(root_entries)}"
        )

    # Confinement via OPENDIR: traversal attempts must be clamped to the root,
    # so the parent directory's secret file must never appear in any listing.
    for escape in ("..", "../", "/../", "../../", "../..//", "/../../"):
        entries = client.list_dir(escape)
        if SECRET_NAME in entries:
            raise AssertionError(
                f"directory traversal via OPENDIR {escape!r} escaped the root: "
                f"parent's {SECRET_NAME!r} is visible ({sorted(entries)}). "
                "Was the daemon built with confinement disabled (ENABLE_CHROOT=no)?"
            )

    # Positive control for file ops: STAT of an in-root file succeeds.
    status = client.stat(INSIDE_NAME)
    if status != TNFS_SUCCESS:
        raise AssertionError(f"STAT {INSIDE_NAME!r} failed with status 0x{status:02x}")

    # Confinement via file ops: a ".." path must be rejected outright.
    for escape in (f"../{SECRET_NAME}", f"../../{SECRET_NAME}"):
        status = client.stat(escape)
        if status == TNFS_SUCCESS:
            raise AssertionError(
                f"STAT {escape!r} unexpectedly succeeded — the outside file is reachable"
            )
        if status != TNFS_EINVAL:
            raise AssertionError(
                f"STAT {escape!r} returned 0x{status:02x}, expected EINVAL (0x0E)"
            )


def main():
    default_server = Path(__file__).resolve().parents[1] / "bin" / "tnfsd"
    server_path = Path(sys.argv[1] if len(sys.argv) > 1 else default_server).resolve()
    if not server_path.is_file():
        raise FileNotFoundError(f"tnfsd binary not found: {server_path}")

    port = find_available_port()
    address = (HOST, port)

    # Layout:
    #   base/               <- parent, outside the jail
    #     secret.txt        <- must never be reachable by a client
    #     root/             <- the served TNFS root
    #       inside.txt      <- must be reachable
    with tempfile.TemporaryDirectory(prefix="tnfsd-confinement-") as base:
        root_dir = os.path.join(base, "root")
        os.mkdir(root_dir)
        with open(os.path.join(root_dir, INSIDE_NAME), "w") as f:
            f.write("in the jail\n")
        with open(os.path.join(base, SECRET_NAME), "w") as f:
            f.write("TOP SECRET - outside the jail\n")

        server = subprocess.Popen(
            (str(server_path), "-p", str(port), root_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        client = TnfsClient(address)
        try:
            wait_until_ready(server, address)
            client.mount("/")
            run_checks(client)
        finally:
            client.close()
            stop_server(server)

    print("PASS: tnfsd confined the client to the served root")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
