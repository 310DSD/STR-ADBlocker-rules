#!/usr/bin/env python3
"""Convert common Clash IP-CIDR advertising lists to FlowGuard endpoints.

The converter is intentionally conservative: provider IP claims become
observe/correlated evidence. They are never promoted to an audited block
without a separate ownership/false-positive review.
"""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path

MAX_ENTRIES = 65_536
DEFAULT_TTL = 86_400


def parse_networks(text: str) -> tuple[set[ipaddress._BaseNetwork], int]:
    networks: set[ipaddress._BaseNetwork] = set()
    rejected = 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [field.strip() for field in line.split(",")]
        kind = fields[0].upper() if fields else ""
        if kind in {"IP-CIDR", "IP-CIDR6", "IP_CIDR", "IP_CIDR6"} and len(fields) >= 2:
            candidate = fields[1]
        elif len(fields) == 1:
            candidate = fields[0]
        else:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            rejected += 1
            continue
        if (
            network.is_private
            or network.is_loopback
            or network.is_link_local
            or network.is_multicast
            or network.is_reserved
            or network.is_unspecified
            or (network.version == 4 and network.prefixlen < 24)
            or (network.version == 6 and network.prefixlen < 64)
        ):
            rejected += 1
            continue
        networks.add(network)
    if len(networks) > MAX_ENTRIES:
        raise ValueError(f"IP feed exceeds {MAX_ENTRIES} entries")
    return networks, rejected


def render(networks: set[ipaddress._BaseNetwork], ruleset: str, ttl: int) -> str:
    lines = ["format=1", f"ruleset={ruleset}"]
    for network in sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen)):
        lines.append(f"{network} 0 0 observe correlated provider 9001 {ttl} active")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ruleset", required=True)
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    args = parser.parse_args()
    if args.ttl <= 0:
        raise SystemExit("--ttl must be positive")
    networks, rejected = parse_networks(args.source.read_text(encoding="utf-8", errors="ignore"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(networks, args.ruleset, args.ttl), encoding="ascii", newline="\n")
    print(f"compiled endpoint_candidates={len(networks)} rejected={rejected} mode=observe_correlated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
