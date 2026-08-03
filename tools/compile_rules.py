#!/usr/bin/env python3
"""Compile a hosts file into STR's mmap-friendly rule format."""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

try:
    from .compile_hosts import normalize_domain
except ImportError:  # Script execution from tools/ keeps the original CLI.
    from compile_hosts import normalize_domain

MAGIC = b"STRRUL1\0"
HEADER = struct.Struct("<8sIIII")


def domains_from_hosts(path: Path) -> list[str]:
    domains: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        candidates = fields[1:] if fields[0] in {"0.0.0.0", "127.0.0.1", "::"} else fields
        for candidate in candidates:
            domain = normalize_domain(candidate)
            if domain:
                domains.add(domain)
    return sorted(domains)


def compile_rules(domains: list[str]) -> bytes:
    encoded = [domain.encode("ascii") for domain in domains]
    offsets = [0]
    payload = bytearray()
    for domain in encoded:
        payload.extend(domain)
        offsets.append(len(payload))
    strings_at = HEADER.size + len(offsets) * 4
    header = HEADER.pack(MAGIC, 1, len(encoded), strings_at, 0)
    return header + struct.pack(f"<{len(offsets)}I", *offsets) + payload


def decode_rules(data: bytes) -> list[str]:
    if len(data) < HEADER.size:
        raise ValueError("rules file is too short")
    magic, version, count, strings_at, reserved = HEADER.unpack_from(data)
    expected_strings_at = HEADER.size + (count + 1) * 4
    if magic != MAGIC or version != 1 or reserved != 0 or strings_at != expected_strings_at or strings_at > len(data):
        raise ValueError("invalid rules header")
    offsets = struct.unpack_from(f"<{count + 1}I", data, HEADER.size)
    payload = data[strings_at:]
    if offsets[0] != 0 or offsets[-1] != len(payload):
        raise ValueError("invalid rules payload bounds")
    domains: list[str] = []
    previous = ""
    for index in range(count):
        start, end = offsets[index], offsets[index + 1]
        if start >= end or end > len(payload):
            raise ValueError(f"invalid rule offset at index {index}")
        try:
            domain = payload[start:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError(f"non-ASCII rule at index {index}") from error
        normalized = normalize_domain(domain)
        if normalized != domain or domain <= previous:
            raise ValueError(f"invalid or unsorted rule at index {index}")
        domains.append(domain)
        previous = domain
    return domains


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hosts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    domains = domains_from_hosts(args.hosts)
    if not domains:
        raise SystemExit("no valid domains")
    data = compile_rules(domains)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(f"compiled rules={len(domains)} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
