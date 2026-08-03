#!/usr/bin/env python3
"""Compile a domain/hosts list into the deterministic module hosts file."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import re
import urllib.request
from pathlib import Path

DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")
BLOCK_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("||"):
        domain = domain[2:]
    domain = domain.removesuffix("^").removeprefix(".")
    if not domain or len(domain) > 253 or not DOMAIN_RE.fullmatch(domain):
        return None
    labels = domain.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        return None
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    return None


def parse_allowlist(text: str) -> set[str]:
    result: set[str] = set()
    for raw in text.splitlines():
        value = raw.split("#", 1)[0].split(maxsplit=1)[0] if raw.split("#", 1)[0].split() else ""
        domain = normalize_domain(value)
        if domain:
            result.add(domain)
    return result


def is_allowed(domain: str, allowlist: set[str]) -> bool:
    parts = domain.split(".")
    return any(".".join(parts[index:]) in allowlist for index in range(len(parts) - 1))


def parse_domains(text: str, allowlist: set[str] | None = None) -> set[str]:
    allowed = allowlist or set()
    result: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        candidate = fields[0] if len(fields) == 1 else fields[1] if fields[0] in BLOCK_IPS else ""
        domain = normalize_domain(candidate)
        if domain and domain != "localhost" and not is_allowed(domain, allowed):
            result.add(domain)
    return result


def render_hosts(domains: set[str], sources: list[str], stamp: str) -> str:
    header = [
        "127.0.0.1 localhost",
        "::1 localhost ip6-localhost ip6-loopback",
        f"# STR-RULESET {stamp}",
    ]
    header.extend(f"# Source: {source}" for source in sources)
    return "\n".join(header + [f"0.0.0.0 {domain}" for domain in sorted(domains)]) + "\n"


def read_source(source: str) -> str:
    path = Path(source)
    if path.exists():
        return path.read_text(encoding="utf-8")
    request = urllib.request.Request(source, headers={"User-Agent": "STR-AdBlocker-builder/0.1"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read().decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--source-label", action="append", help="header label; defaults to each source")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--min-rules", type=int, default=10_000)
    parser.add_argument("--max-rules", type=int, default=2_500_000)
    parser.add_argument("--stamp", help="UTC ruleset stamp; defaults to the current time")
    args = parser.parse_args()

    allow_text = args.allowlist.read_text(encoding="utf-8") if args.allowlist else ""
    allowlist = parse_allowlist(allow_text)
    domains: set[str] = set()
    for source in args.source:
        domains.update(parse_domains(read_source(source), allowlist))
    if not args.min_rules <= len(domains) <= args.max_rules:
        raise SystemExit(f"refusing suspicious ruleset with {len(domains)} entries")
    stamp = args.stamp or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    labels = args.source_label or args.source
    if len(labels) != len(args.source):
        raise SystemExit("--source-label count must match --source count")
    args.output.write_text(render_hosts(domains, labels, stamp), encoding="utf-8", newline="\n")
    print(f"compiled {len(domains)} domains into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
