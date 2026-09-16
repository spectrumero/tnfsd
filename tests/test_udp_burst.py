#!/usr/bin/env python3
"""Regression test for draining queued UDP datagrams on Linux."""

import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HOST = "127.0.0.1"
ANY_ADDRESS = "0.0.0.0"
BURST_SIZE = 32
TNFS_UMOUNT = 0x01
TNFS_EBADSESSION = 0xFF


def invalid_session_request(sequence_number):
    return b"\xff\xff" + bytes((sequence_number, TNFS_UMOUNT))


def invalid_session_response(sequence_number):
    return b"\x00\x00" + bytes(
        (sequence_number, TNFS_UMOUNT, TNFS_EBADSESSION)
    )


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


def assert_udp_burst_is_drained(server, client, address):
    expected_responses = {
        invalid_session_response(sequence_number)
        for sequence_number in range(1, BURST_SIZE + 1)
    }
    received_responses = set()

    os.kill(server.pid, signal.SIGSTOP)
    _, status = os.waitpid(server.pid, os.WUNTRACED)
    if not os.WIFSTOPPED(status):
        raise RuntimeError("tnfsd exited instead of stopping for the burst test")

    for sequence_number in range(1, BURST_SIZE + 1):
        client.sendto(invalid_session_request(sequence_number), address)

    os.kill(server.pid, signal.SIGCONT)

    deadline = time.monotonic() + 5
    while received_responses != expected_responses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        client.settimeout(min(0.2, remaining))
        try:
            response, _ = client.recvfrom(532)
        except socket.timeout:
            continue

        if response in expected_responses:
            received_responses.add(response)

    missing_responses = expected_responses - received_responses
    if missing_responses:
        missing_sequences = sorted(response[2] for response in missing_responses)
        raise AssertionError(
            f"received {len(received_responses)}/{BURST_SIZE} responses; "
            f"missing sequences: {missing_sequences}"
        )


def stop_server(server):
    if server.poll() is not None:
        return

    os.kill(server.pid, signal.SIGCONT)
    server.send_signal(signal.SIGINT)
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)


def main():
    default_server = Path(__file__).resolve().parents[1] / "bin" / "tnfsd"
    server_path = Path(sys.argv[1] if len(sys.argv) > 1 else default_server).resolve()
    if not server_path.is_file():
        raise FileNotFoundError(f"tnfsd binary not found: {server_path}")

    port = find_available_port()
    address = (HOST, port)

    with tempfile.TemporaryDirectory(prefix="tnfsd-udp-burst-") as root_dir:
        server = subprocess.Popen(
            (str(server_path), "-p", str(port), root_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                wait_until_ready(server, address)
                assert_udp_burst_is_drained(server, client, address)
        finally:
            stop_server(server)

    print(f"PASS: tnfsd responded to all {BURST_SIZE} queued UDP requests")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
