#!/usr/bin/env python3

import shlex
import subprocess
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1] / "src"


def main_compile_command(os_name, enable_chroot=None):
    command = ["make", "-Bn", "XA=true", f"OS={os_name}"]
    if enable_chroot is not None:
        command.append(f"ENABLE_CHROOT={enable_chroot}")
    command.append("all")

    result = subprocess.run(
        command,
        cwd=SOURCE_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        if "-o main.o main.c" in line:
            return line

    raise AssertionError(f"main.c compile command not found in:\n{result.stdout}")


def assert_chroot_flag(os_name, enable_chroot, expected):
    compile_command = main_compile_command(os_name, enable_chroot)
    has_flag = "-DENABLE_CHROOT" in shlex.split(compile_command)
    if has_flag != expected:
        raise AssertionError(compile_command)


def main():
    assert_chroot_flag("LINUX", None, True)
    assert_chroot_flag("LINUX", "yes", True)
    assert_chroot_flag("LINUX", "no", False)
    assert_chroot_flag("BSD", None, True)
    assert_chroot_flag("Windows_NT", None, False)


if __name__ == "__main__":
    main()
