#!/usr/bin/env python3
"""Regression test: malformed requests must not crash or leak the daemon.

Every request arrives in a 532-byte stack buffer (rxbuf in tnfs_decode), and
tnfs_decode accepts anything at least TNFS_HEADERSZ long, so a handler that
trusts a client-supplied length reads off the end of it.  Three did:

  * WRITEBLOCK took the declared size straight from the request and passed
    it to write(), so a client could claim 65535 bytes, send 8, and have the
    daemon write tens of kilobytes of its own stack into a file it could
    then read back.
  * OPENFILE (deprecated, 0x20) computed its memcpy length as bufsz - 2,
    which goes negative -- and converts to a huge size_t -- on a datagram
    with no payload.  A four-byte packet aborted the process.
  * READDIRX sent its EOF reply and then fell through and built a second
    one, answering a single request with two datagrams.

Each check below fails against a daemon without the corresponding fix.
"""

import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOST = "127.0.0.1"

TNFS_MOUNT = 0x00
TNFS_OPENDIRX = 0x17
TNFS_READDIRX = 0x18
TNFS_OPENFILE_OLD = 0x20
TNFS_WRITEBLOCK = 0x22
TNFS_CLOSEFILE = 0x23
TNFS_OPENFILE = 0x29

TNFS_SUCCESS = 0x00
TNFS_EOF = 0x21

PROTOVERSION = b"\x03\x01"

# src/tnfs_file.h
TNFS_O_WRONLY = 0x0002
TNFS_O_CREAT = 0x0100
TNFS_O_TRUNC = 0x0200

PAYLOAD = b"ABCDEFGH"
DECLARED_SIZE = 60000
LEAK_NAME = "leak.bin"


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


class Client:
    """Just enough TNFS-over-UDP to drive the handlers under test."""

    def __init__(self, address):
        self.address = address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sid = 0
        self.seqno = 0

    def close(self):
        self.socket.close()

    def send(self, command, payload=b""):
        self.seqno = (self.seqno + 1) & 0xFF
        self.socket.sendto(
            struct.pack("<HBB", self.sid, self.seqno, command) + payload, self.address
        )

    def recv(self, timeout=5):
        self.socket.settimeout(timeout)
        try:
            return self.socket.recv(532)
        except socket.timeout:
            return None

    def exchange(self, command, payload=b"", timeout=5):
        self.send(command, payload)
        response = self.recv(timeout)
        if response is None:
            raise AssertionError(f"no reply to command 0x{command:02x}")
        return response[4], response[5:]

    def collect(self, timeout=0.5):
        """Every datagram that arrives within the window, not just the first."""
        replies = []
        self.socket.settimeout(timeout)
        while True:
            try:
                replies.append(self.socket.recv(532))
            except socket.timeout:
                return replies

    def mount(self):
        status, _ = self.exchange(TNFS_MOUNT, PROTOVERSION + b"/\x00" + b"\x00" + b"\x00")
        if status != TNFS_SUCCESS:
            raise AssertionError(f"MOUNT failed with status 0x{status:02x}")
        # The reply carries the assigned sid; re-mount so we can read it back.
        self.send(TNFS_MOUNT, PROTOVERSION + b"/\x00" + b"\x00" + b"\x00")
        response = self.recv()
        if response is None:
            raise AssertionError("no reply to MOUNT")
        self.sid = struct.unpack("<H", response[0:2])[0]


def check_writeblock_does_not_overread(client, root_dir, failures):
    """A declared size larger than the datagram must not reach write()."""
    flags = TNFS_O_WRONLY | TNFS_O_CREAT | TNFS_O_TRUNC
    status, body = client.exchange(
        TNFS_OPENFILE, struct.pack("<HH", flags, 0o644) + f"/{LEAK_NAME}\x00".encode()
    )
    if status != TNFS_SUCCESS:
        failures.append(f"OPENFILE for the write test failed with status 0x{status:02x}")
        return
    fd = body[0]

    client.exchange(
        TNFS_WRITEBLOCK, bytes((fd,)) + struct.pack("<H", DECLARED_SIZE) + PAYLOAD
    )
    client.exchange(TNFS_CLOSEFILE, bytes((fd,)))

    written = os.path.getsize(Path(root_dir) / LEAK_NAME)
    if written > len(PAYLOAD):
        failures.append(
            f"WRITEBLOCK declared {DECLARED_SIZE} bytes and sent {len(PAYLOAD)}, "
            f"but the daemon wrote {written} -- {written - len(PAYLOAD)} bytes of "
            f"server memory leaked into a client-readable file"
        )
    else:
        print(f"  WRITEBLOCK: wrote {written} bytes for a {len(PAYLOAD)}-byte payload (ok)")


def check_deprecated_open_survives_empty_payload(client, server, failures):
    """OPENFILE 0x20 with no payload must not abort the process."""
    client.send(TNFS_OPENFILE_OLD)
    client.recv(timeout=1)  # a reply is welcome but not required

    time.sleep(0.3)
    if server.poll() is not None:
        failures.append(
            f"a 4-byte OPENFILE (0x20) killed the daemon (status {server.returncode})"
        )
        return False

    # Still alive is not enough; it has to still be answering.
    try:
        client.exchange(TNFS_OPENDIRX, struct.pack("<BBH", 0, 0, 0) + b"\x00" + b"/\x00")
    except AssertionError:
        failures.append("the daemon stopped answering after a 4-byte OPENFILE (0x20)")
        return False

    print("  OPENFILE (0x20) with an empty payload: daemon survived and still answers (ok)")
    return True


def check_readdirx_eof_sends_one_reply(client, failures):
    """At EOF, READDIRX must answer once, not twice."""
    status, body = client.exchange(
        TNFS_OPENDIRX, struct.pack("<BBH", 0, 0, 0) + b"\x00" + b"/\x00"
    )
    if status != TNFS_SUCCESS:
        failures.append(f"OPENDIRX failed with status 0x{status:02x}")
        return
    handle = body[0]

    def request_once(label):
        """One READDIRX, returning every datagram it drew back."""
        client.send(TNFS_READDIRX, bytes((handle, 0)))
        replies = client.collect()
        if not replies:
            failures.append(f"READDIRX stopped replying {label}")
            return None
        if len(replies) != 1:
            failures.append(
                f"READDIRX {label} answered one request with {len(replies)} "
                "datagrams: " + ", ".join(r.hex() for r in replies)
            )
            return None
        return replies[0]

    # Drain the listing so the handle sits at EOF.
    for _ in range(32):
        reply = request_once("while draining the listing")
        if reply is None:
            return
        if reply[4] == TNFS_EOF:
            break
    else:
        failures.append("READDIRX never reached EOF")
        return

    # One more request, now that it is definitely at EOF.
    if request_once("at EOF") is not None:
        print("  READDIRX at EOF: one reply per request (ok)")


def main():
    default_server = Path(__file__).resolve().parents[1] / "bin" / "tnfsd"
    server_path = Path(sys.argv[1] if len(sys.argv) > 1 else default_server).resolve()
    if not server_path.is_file():
        raise FileNotFoundError(f"tnfsd binary not found: {server_path}")

    failures = []

    with tempfile.TemporaryDirectory(prefix="tnfsd-malformed-") as root_dir:
        port = find_available_port()
        address = (HOST, port)
        server = subprocess.Popen(
            (str(server_path), "-p", str(port), root_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        client = Client(address)
        try:
            wait_until_ready(server, address)
            client.mount()

            check_writeblock_does_not_overread(client, root_dir, failures)
            check_readdirx_eof_sends_one_reply(client, failures)
            # Last: it is the one that can take the daemon down.
            check_deprecated_open_survives_empty_payload(client, server, failures)
        finally:
            client.close()
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("PASS: malformed requests are rejected without crashing or over-reading")
    return 0


if __name__ == "__main__":
    sys.exit(main())
