#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0+
"""Reject unsupported or unpatched TF-A Mbed TLS dependencies."""
from pathlib import Path
import re
import sys


def check(root):
    include = Path(root) / "include/mbedtls"
    headers = [include / "build_info.h", include / "version.h"]
    text = "\n".join(p.read_text() for p in headers if p.is_file())
    version = []
    for part in ("MAJOR", "MINOR", "PATCH"):
        match = re.search(r"^#define\s+MBEDTLS_VERSION_" + part + r"\s+(\d+)\s*$",
                          text, re.MULTILINE)
        if not match:
            raise ValueError("cannot determine Mbed TLS version from source headers")
        version.append(int(match[1]))
    version = tuple(version)
    if version[:2] != (3, 6) or version[2] < 7:
        raise ValueError("TF-A requires Mbed TLS 3.6.7 or later 3.6.x; found " +
                         ".".join(map(str, version)))
    return version


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: check-mbedtls.py <MBEDTLS_DIR>")
    try:
        version = check(sys.argv[1])
    except (OSError, ValueError) as error:
        sys.exit(str(error))
    print("TF-A Mbed TLS dependency: " + ".".join(map(str, version)))
