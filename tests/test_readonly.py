#!/usr/bin/env python3
"""Regression test for TNFS read-only mode (the -r flag).

When started with -r, the daemon must let clients list and download files
but must refuse every operation that could modify the served filesystem.
Two independent gates enforce this:

  * is_cmd_allowed() in src/auth.c rejects the mutating commands outright
    (MKDIR, RMDIR, WRITEBLOCK, UNLINK, CHMOD, RENAME) before dispatch, so
    they answer with EPERM.
  * is_open_allowed() rejects an OPEN whose flags request write access
    (O_WRONLY/O_RDWR, O_APPEND, O_CREAT, O_TRUNC, O_EXCL), so a client
    cannot obtain a writable descriptor in the first place.

The test drives a real daemon over UDP: it checks that reads still work,
that every mutating path is refused with EPERM, and - the part a protocol
check alone would miss - that the served directory on disk is byte-for-byte
unchanged afterwards. It then runs the same daemon *without* -r and
confirms those same operations succeed, so a silently disabled read-only
mode cannot pass.

Usage:
    test_readonly.py [path/to/tnfsd]        spawn a daemon and test it
    test_readonly.py --server HOST[:PORT]   test an already-running daemon

The --server form is non-destructive: every mutating probe targets a
unique path that does not exist, so a server that turns out *not* to be
read-only cannot lose data (anything it does create is cleaned up).
"""

import os
import random
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HOST = "127.0.0.1"
ANY_ADDRESS = "0.0.0.0"
DEFAULT_PORT = 16384

# Command bytes
TNFS_MOUNT = 0x00
TNFS_OPENDIR = 0x10
TNFS_READDIR = 0x11
TNFS_CLOSEDIR = 0x12
TNFS_MKDIR = 0x13
TNFS_RMDIR = 0x14
TNFS_OPENFILE_OLD = 0x20
TNFS_READBLOCK = 0x21
TNFS_WRITEBLOCK = 0x22
TNFS_CLOSEFILE = 0x23
TNFS_STATFILE = 0x24
TNFS_UNLINKFILE = 0x26
TNFS_CHMODFILE = 0x27
TNFS_RENAMEFILE = 0x28
TNFS_OPENFILE = 0x29

# Status bytes
TNFS_SUCCESS = 0x00
TNFS_EPERM = 0x01
TNFS_EOF = 0x21

# Open flags
TNFS_O_RDONLY = 0x0001
TNFS_O_WRONLY = 0x0002
TNFS_O_RDWR = 0x0003
TNFS_O_APPEND = 0x0008
TNFS_O_CREAT = 0x0100
TNFS_O_TRUNC = 0x0200
TNFS_O_EXCL = 0x0400

WRITE_FLAGS = (
    ("O_WRONLY", TNFS_O_WRONLY),
    ("O_RDWR", TNFS_O_RDWR),
    ("O_APPEND", TNFS_O_RDONLY | TNFS_O_APPEND),
    ("O_CREAT", TNFS_O_RDONLY | TNFS_O_CREAT),
    ("O_TRUNC", TNFS_O_RDONLY | TNFS_O_TRUNC),
    ("O_EXCL", TNFS_O_RDONLY | TNFS_O_EXCL),
    ("O_WRONLY|O_CREAT|O_TRUNC", TNFS_O_WRONLY | TNFS_O_CREAT | TNFS_O_TRUNC),
)

DATA_NAME = "readable.txt"
DATA_CONTENT = b"the client may read this but never change it\n"
SUBDIR_NAME = "subdir"


def status_name(status):
    names = {
        TNFS_SUCCESS: "SUCCESS",
        TNFS_EPERM: "EPERM",
        0x02: "ENOENT",
        0x06: "EBADF",
        0x09: "EACCES",
        0x0B: "EEXIST",
        0x0D: "EISDIR",
        0x0E: "EINVAL",
        0x14: "EROFS",
        TNFS_EOF: "EOF",
    }
    return f"0x{status:02x} ({names.get(status, 'unknown')})"


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
    """A minimal TNFS-over-UDP client: just enough to test read-only mode."""

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
                response = self._sock.recv(65535)
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
            raise RuntimeError(f"MOUNT failed with status {status_name(status)}")
        self._sid = header_sid
        return header_sid

    # --- directory operations ---

    def opendir(self, path):
        status, data, _ = self._request(TNFS_OPENDIR, path.encode() + b"\x00")
        handle = data[0] if (status == TNFS_SUCCESS and data) else None
        return status, handle

    def readdir_names(self, handle):
        names = []
        for _ in range(1000):  # generous guard against a runaway handle
            status, data, _ = self._request(TNFS_READDIR, bytes((handle,)))
            if status == TNFS_EOF:
                break
            if status != TNFS_SUCCESS:
                raise RuntimeError(f"READDIR returned status {status_name(status)}")
            names.append(data.split(b"\x00", 1)[0].decode(errors="replace"))
        return names

    def closedir(self, handle):
        status, _, _ = self._request(TNFS_CLOSEDIR, bytes((handle,)))
        return status

    def list_dir(self, path):
        status, handle = self.opendir(path)
        if status != TNFS_SUCCESS or handle is None:
            raise RuntimeError(f"OPENDIR {path!r} failed with status {status_name(status)}")
        try:
            return self.readdir_names(handle)
        finally:
            self.closedir(handle)

    def mkdir(self, path):
        status, _, _ = self._request(TNFS_MKDIR, path.encode() + b"\x00")
        return status

    def rmdir(self, path):
        status, _, _ = self._request(TNFS_RMDIR, path.encode() + b"\x00")
        return status

    # --- file operations ---

    def stat(self, path):
        status, _, _ = self._request(TNFS_STATFILE, path.encode() + b"\x00")
        return status

    def open(self, path, flags, mode=0o644):
        payload = struct.pack("<HH", flags, mode) + path.encode() + b"\x00"
        status, data, _ = self._request(TNFS_OPENFILE, payload)
        handle = data[0] if (status == TNFS_SUCCESS and data) else None
        return status, handle

    def open_deprecated(self, path, old_flags, old_mode=0x00):
        """The pre-1.0 OPEN: one flags byte, one mode byte, then the name."""
        payload = bytes((old_flags, old_mode)) + path.encode() + b"\x00"
        status, data, _ = self._request(TNFS_OPENFILE_OLD, payload)
        handle = data[0] if (status == TNFS_SUCCESS and data) else None
        return status, handle

    def read(self, handle, size):
        status, data, _ = self._request(TNFS_READBLOCK, bytes((handle,)) + struct.pack("<H", size))
        if status != TNFS_SUCCESS:
            return status, b""
        # reply is a 16-bit count followed by the data
        return status, data[2:]

    def write(self, handle, data):
        payload = bytes((handle,)) + struct.pack("<H", len(data)) + data
        status, _, _ = self._request(TNFS_WRITEBLOCK, payload)
        return status

    def close_file(self, handle):
        status, _, _ = self._request(TNFS_CLOSEFILE, bytes((handle,)))
        return status

    def unlink(self, path):
        status, _, _ = self._request(TNFS_UNLINKFILE, path.encode() + b"\x00")
        return status

    def chmod(self, path, mode):
        payload = struct.pack("<H", mode) + path.encode() + b"\x00"
        status, _, _ = self._request(TNFS_CHMODFILE, payload)
        return status

    def rename(self, source, dest):
        payload = source.encode() + b"\x00" + dest.encode() + b"\x00"
        status, _, _ = self._request(TNFS_RENAMEFILE, payload)
        return status


def expect_denied(what, status):
    """A mutating operation must be refused with EPERM."""
    if status == TNFS_SUCCESS:
        raise AssertionError(f"{what} succeeded - the server is NOT read-only")
    if status != TNFS_EPERM:
        raise AssertionError(
            f"{what} returned {status_name(status)}, expected EPERM (0x01). "
            "It was refused, but not by the read-only gate."
        )


def check_reads_work(client, filename):
    """Positive controls: listing and downloading must still work."""
    status = client.stat(filename)
    if status != TNFS_SUCCESS:
        raise AssertionError(f"STAT {filename!r} failed with status {status_name(status)}")

    status, handle = client.open(filename, TNFS_O_RDONLY)
    if status != TNFS_SUCCESS or handle is None:
        raise AssertionError(
            f"read-only OPEN of {filename!r} failed with status {status_name(status)} - "
            "read-only mode must still permit downloads"
        )
    try:
        status, data = client.read(handle, 512)
        if status not in (TNFS_SUCCESS, TNFS_EOF):
            raise AssertionError(f"READ of {filename!r} failed with status {status_name(status)}")
    finally:
        client.close_file(handle)
    return data


def check_writes_denied(client, existing_file, existing_dir, scratch):
    """Every mutating operation must come back EPERM."""
    expect_denied(f"MKDIR {scratch!r}", client.mkdir(scratch))
    expect_denied(f"RMDIR {existing_dir!r}", client.rmdir(existing_dir))
    expect_denied(f"UNLINK {scratch!r}", client.unlink(scratch))
    expect_denied(f"CHMOD {scratch!r}", client.chmod(scratch, 0o777))
    expect_denied(f"RENAME {scratch!r}", client.rename(scratch, scratch + ".moved"))

    for label, flags in WRITE_FLAGS:
        status, handle = client.open(scratch, flags)
        if status == TNFS_SUCCESS and handle is not None:
            client.close_file(handle)
            client.unlink(scratch)  # best effort cleanup; also denied when read-only
            raise AssertionError(
                f"OPEN {scratch!r} with {label} succeeded - a writable descriptor was handed out"
            )
        expect_denied(f"OPEN {scratch!r} with {label}", status)

    # The deprecated OPEN (0x20) funnels into the same handler, so it must be
    # gated too - otherwise it is a way around the check.
    status, handle = client.open_deprecated(scratch, TNFS_O_WRONLY)
    if status == TNFS_SUCCESS and handle is not None:
        client.close_file(handle)
        client.unlink(scratch)
        raise AssertionError(
            "deprecated OPEN (0x20) with O_WRONLY succeeded - it bypasses the read-only gate"
        )
    expect_denied("deprecated OPEN (0x20) with O_WRONLY", status)

    # WRITE must be refused at the command level, even against a descriptor
    # that was legitimately opened for reading.
    status, handle = client.open(existing_file, TNFS_O_RDONLY)
    if status != TNFS_SUCCESS or handle is None:
        raise AssertionError(
            f"could not open {existing_file!r} for reading: {status_name(status)}"
        )
    try:
        expect_denied("WRITE to a read-only descriptor", client.write(handle, b"clobbered"))
    finally:
        client.close_file(handle)


def snapshot(root):
    """Record every path under root with its size, mode and content hash."""
    state = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            info = os.lstat(full)
            content = None
            if stat.S_ISREG(info.st_mode):
                with open(full, "rb") as f:
                    content = f.read()
            state[rel] = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), content)
    return state


def diff_snapshots(before, after):
    problems = []
    for path in sorted(set(before) - set(after)):
        problems.append(f"{path} was deleted")
    for path in sorted(set(after) - set(before)):
        problems.append(f"{path} was created")
    for path in sorted(set(before) & set(after)):
        was, now = before[path], after[path]
        if was[1] != now[1]:
            problems.append(f"{path} mode changed {was[1]:o} -> {now[1]:o}")
        if was[2] != now[2]:
            problems.append(f"{path} content changed")
    return problems


def populate(root):
    with open(os.path.join(root, DATA_NAME), "wb") as f:
        f.write(DATA_CONTENT)
    os.mkdir(os.path.join(root, SUBDIR_NAME))


def spawn(server_path, root_dir, port, read_only):
    args = [str(server_path), "-p", str(port)]
    if read_only:
        args.append("-r")
    args.append(root_dir)
    return subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_read_only_case(server_path):
    """Start the daemon with -r and confirm nothing can be changed."""
    port = find_available_port()
    address = (HOST, port)

    with tempfile.TemporaryDirectory(prefix="tnfsd-readonly-") as root_dir:
        populate(root_dir)
        before = snapshot(root_dir)

        server = spawn(server_path, root_dir, port, read_only=True)
        client = TnfsClient(address)
        try:
            wait_until_ready(server, address)
            client.mount("/")

            entries = client.list_dir("/")
            if DATA_NAME not in entries:
                raise AssertionError(
                    f"expected {DATA_NAME!r} in the root listing, got {sorted(entries)}"
                )

            data = check_reads_work(client, DATA_NAME)
            if data != DATA_CONTENT:
                raise AssertionError(f"READ returned {data!r}, expected {DATA_CONTENT!r}")

            check_writes_denied(client, DATA_NAME, SUBDIR_NAME, "scratch.txt")
        finally:
            client.close()
            stop_server(server)

        problems = diff_snapshots(before, snapshot(root_dir))
        if problems:
            raise AssertionError(
                "the served directory changed under a read-only server: " + "; ".join(problems)
            )

    print("PASS: with -r, reads work and every write path is refused with EPERM")


def run_read_write_control(server_path):
    """Without -r the same operations must succeed.

    This is what stops the test passing vacuously: if the mutating requests
    were failing for some unrelated reason (a malformed payload, say), they
    would fail here too and this control would catch it.
    """
    port = find_available_port()
    address = (HOST, port)

    with tempfile.TemporaryDirectory(prefix="tnfsd-readwrite-") as root_dir:
        populate(root_dir)

        server = spawn(server_path, root_dir, port, read_only=False)
        client = TnfsClient(address)
        try:
            wait_until_ready(server, address)
            client.mount("/")

            status, handle = client.open(
                "control.txt", TNFS_O_WRONLY | TNFS_O_CREAT | TNFS_O_TRUNC
            )
            if status != TNFS_SUCCESS or handle is None:
                raise AssertionError(
                    "without -r, OPEN for writing failed with status "
                    f"{status_name(status)} - the write path is broken independently of "
                    "read-only mode, so the read-only checks prove nothing"
                )
            status = client.write(handle, b"written by the control run\n")
            client.close_file(handle)
            if status != TNFS_SUCCESS:
                raise AssertionError(f"without -r, WRITE failed with status {status_name(status)}")

            # CHMOD is deliberately absent here: tnfs_chmod() in
            # src/tnfs_file.c is an empty stub that never sends a reply, so a
            # read-write server simply times out on it. The read-only run
            # still covers CHMOD, because the -r gate refuses the command
            # before dispatch and does answer with EPERM.
            for what, status in (
                ("MKDIR", client.mkdir("control-dir")),
                ("RENAME", client.rename("control.txt", "control-moved.txt")),
                ("UNLINK", client.unlink("control-moved.txt")),
                ("RMDIR", client.rmdir("control-dir")),
            ):
                if status != TNFS_SUCCESS:
                    raise AssertionError(
                        f"without -r, {what} failed with status {status_name(status)} - "
                        "the read-only checks would pass for the wrong reason"
                    )
        finally:
            client.close()
            stop_server(server)

    print("PASS: without -r, the same operations succeed (the checks are meaningful)")


def pick_probe_targets(client):
    """Find a readable regular file and a directory in a live server's root.

    OPENDIR decides which is which: STAT and OPEN both succeed on a
    directory, so they cannot tell the two apart on their own.
    """
    entries = [name for name in client.list_dir("/") if name not in (".", "..")]
    existing_file = None
    existing_dir = None

    for name in entries:
        if existing_file is not None and existing_dir is not None:
            break

        status, handle = client.opendir(name)
        if status == TNFS_SUCCESS and handle is not None:
            client.closedir(handle)
            if existing_dir is None:
                existing_dir = name
            continue

        if existing_file is None and client.stat(name) == TNFS_SUCCESS:
            status, handle = client.open(name, TNFS_O_RDONLY)
            if status == TNFS_SUCCESS and handle is not None:
                status, _ = client.read(handle, 1)
                client.close_file(handle)
                if status in (TNFS_SUCCESS, TNFS_EOF):
                    existing_file = name

    return entries, existing_file, existing_dir


def run_live_server_case(address):
    """Probe an already-running daemon. Nothing existing is ever targeted."""
    scratch = f"tnfsd-readonly-probe-{os.getpid()}-{random.randrange(1 << 30):08x}"

    client = TnfsClient(address)
    try:
        client.mount("/")
        entries, existing_file, existing_dir = pick_probe_targets(client)
        print(f"  mounted {address[0]}:{address[1]}, root has {len(entries)} entries")

        if existing_file is not None:
            data = check_reads_work(client, existing_file)
            print(f"  reads work: downloaded {len(data)} bytes from {existing_file!r}")
        else:
            print("  note: no readable file in the root, skipping the download check")

        # Every mutating probe below targets a path that does not exist, so a
        # server that is not read-only cannot destroy anything.
        status = client.mkdir(scratch)
        if status == TNFS_SUCCESS:
            removed = client.rmdir(scratch) == TNFS_SUCCESS
            raise AssertionError(
                f"MKDIR {scratch!r} succeeded - the server is NOT read-only"
                + ("" if removed else f" (could not remove the directory it created)")
            )
        expect_denied(f"MKDIR {scratch!r}", status)
        expect_denied(f"RMDIR {scratch!r}", client.rmdir(scratch))
        expect_denied(f"UNLINK {scratch!r}", client.unlink(scratch))
        expect_denied(f"CHMOD {scratch!r}", client.chmod(scratch, 0o777))
        expect_denied(f"RENAME {scratch!r}", client.rename(scratch, scratch + ".moved"))

        for label, flags in WRITE_FLAGS:
            status, handle = client.open(scratch, flags)
            if status == TNFS_SUCCESS and handle is not None:
                client.close_file(handle)
                client.unlink(scratch)
                raise AssertionError(
                    f"OPEN {scratch!r} with {label} succeeded - the server is NOT read-only "
                    f"(a file named {scratch!r} may have been created; removal was attempted)"
                )
            expect_denied(f"OPEN {scratch!r} with {label}", status)

        status, handle = client.open_deprecated(scratch, TNFS_O_WRONLY)
        if status == TNFS_SUCCESS and handle is not None:
            client.close_file(handle)
            client.unlink(scratch)
            raise AssertionError("deprecated OPEN (0x20) with O_WRONLY succeeded")
        expect_denied("deprecated OPEN (0x20) with O_WRONLY", status)

        if existing_file is not None:
            status, handle = client.open(existing_file, TNFS_O_RDONLY)
            if status == TNFS_SUCCESS and handle is not None:
                try:
                    # The descriptor is O_RDONLY, so even an ungated server
                    # would only get EBADF here - the file cannot be damaged.
                    expect_denied(
                        "WRITE to a read-only descriptor", client.write(handle, b"probe")
                    )
                finally:
                    client.close_file(handle)

        if existing_dir is not None:
            # A real directory, but RMDIR must be refused before it is touched.
            expect_denied(f"RMDIR {existing_dir!r}", client.rmdir(existing_dir))
    finally:
        client.close()

    print(f"PASS: the server at {address[0]}:{address[1]} is read-only")


def parse_address(text):
    if ":" in text:
        host, _, port = text.rpartition(":")
        return (host, int(port))
    return (text, DEFAULT_PORT)


def main():
    args = sys.argv[1:]

    if args and args[0] == "--server":
        if len(args) != 2:
            raise SystemExit("usage: test_readonly.py --server HOST[:PORT]")
        run_live_server_case(parse_address(args[1]))
        return

    default_server = Path(__file__).resolve().parents[1] / "bin" / "tnfsd"
    server_path = Path(args[0] if args else default_server).resolve()
    if not server_path.is_file():
        raise FileNotFoundError(f"tnfsd binary not found: {server_path}")

    run_read_only_case(server_path)
    run_read_write_control(server_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
