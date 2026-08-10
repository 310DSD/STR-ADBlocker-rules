#!/usr/bin/env python3
"""Compile the bounded network-safe provider subset used by FlowGuard F2.

The compiler is deliberately separate from the resident Go daemon. It accepts
hosts/domain and a small uBlock/AdGuard network subset, rejects browser-only
cosmetic/procedural rules, emits the existing deterministic rules binary, and
optionally emits a validated endpoint sidecar.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

try:
    from .compile_hosts import normalize_domain, parse_allowlist
    from .compile_rules import compile_rules
except ImportError:  # Script execution from tools/ keeps the original CLI.
    from compile_hosts import normalize_domain, parse_allowlist
    from compile_rules import compile_rules

COMPILER_VERSION = "str-f2-policy-1"
MAX_DOMAIN_BYTES = 253
ENDPOINT_RE = re.compile(r"^(?P<address>[^,\s]+)[,\s]+(?P<protocol>\d+)[,\s]+(?P<port>\d+)[,\s]+(?P<action>observe|allow|block)[,\s]+(?P<confidence>unknown|observed|correlated|audited)[,\s]+(?P<source>unknown|provider|dns|tls|quic|companion)[,\s]+(?P<policy>\d+)[,\s]+(?P<ttl>\d+)(?:[,\s]+active)?$", re.I)
SOURCE_URLS = {
    "hagezi-normal": "https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/adblock/multi.txt",
    "antiad-easylist": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt",
    "1hosts-lite": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt",
    "adguard-dns": "https://filters.adtidy.org/extension/chromium/filters/15.txt",
    "adguard-base": "https://filters.adtidy.org/extension/chromium/filters/2.txt",
    "adguard-chinese": "https://filters.adtidy.org/extension/chromium/filters/224.txt",
    "banad": "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "oisd-big": "https://big.oisd.nl",
}


@dataclass(frozen=True)
class ProviderResult:
    domains: tuple[str, ...]
    unsupported: int
    endpoint_lines: tuple[str, ...]


def allowed_domain(domain: str, allowlist: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[index:]) in allowlist for index in range(len(labels) - 1))


def _adblock_domain(token: str) -> str | None:
    token = token.strip()
    if not token.startswith("||"):
        return None
    token = token[2:]
    token = token.split("^", 1)[0]
    token = token.split("/", 1)[0]
    return normalize_domain(token)


def parse_provider_line(raw: str, allowlist: set[str]) -> tuple[str | None, bool]:
    """Return (domain, unsupported) for one provider line.

    Unsupported is true only for a non-empty rule that is not in the bounded
    network subset. Empty comments and valid allowlist exceptions are ignored.
    """

    line = raw.strip()
    if line.startswith("#") and not line.startswith("##"):
        return None, False
    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
    if not line:
        return None, False
    if line.startswith("@@"):
        return None, False
    if line.startswith("||"):
        # Keep this parser byte-for-byte compatible with bin/update.sh. The
        # production updater intentionally accepts only the bounded
        # ||domain^ form; browser-only/options rules are ignored.
        if not re.fullmatch(r"\|\|[a-z0-9.-]+\^(?:\$)?", line):
            return None, True
        domain = _adblock_domain(line)
        if domain is None:
            return None, True
        return (None if allowed_domain(domain, allowlist) else domain), False
    fields = line.split()
    if len(fields) == 1:
        domain = normalize_domain(fields[0])
        if domain is None:
            return None, True
        return (None if allowed_domain(domain, allowlist) else domain), False
    if fields[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"} and len(fields) >= 2:
        domain = normalize_domain(fields[1])
        if domain is None:
            return None, True
        return (None if allowed_domain(domain, allowlist) else domain), False
    return None, True


def parse_provider(text: str, allowlist: set[str]) -> ProviderResult:
    domains: set[str] = set()
    unsupported = 0
    for raw in text.splitlines():
        domain, rejected = parse_provider_line(raw, allowlist)
        unsupported += int(rejected)
        if domain and domain != "localhost":
            domains.add(domain)
    return ProviderResult(tuple(sorted(domains)), unsupported, ())


def parse_endpoint(text: str, maximum: int = 65536) -> tuple[str, ...]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("format=") or line.startswith("ruleset="):
            continue
        match = ENDPOINT_RE.fullmatch(line)
        if not match:
            raise ValueError(f"invalid endpoint rule: {line!r}")
        address = match.group("address")
        try:
            prefix = ipaddress.ip_network(address, strict=False)
        except ValueError as error:
            raise ValueError(f"invalid endpoint address: {address!r}") from error
        protocol = int(match.group("protocol"))
        port = int(match.group("port"))
        policy_id = int(match.group("policy"))
        ttl = int(match.group("ttl"))
        if protocol not in (0, 6, 17) or port > 65535 or policy_id > 0xFFFFFFFF or ttl <= 0:
            raise ValueError(f"invalid endpoint bounds: {line!r}")
        if match.group("action").lower() == "block" and match.group("confidence").lower() != "audited":
            raise ValueError("endpoint blocks require audited confidence")
        lines.append("%s %d %d %s %s %s %d %d active" % (
            prefix.with_prefixlen,
            protocol,
            port,
            match.group("action").lower(),
            match.group("confidence").lower(),
            match.group("source").lower(),
            policy_id,
            ttl,
        ))
        if len(lines) > maximum:
            raise ValueError("endpoint capacity exceeded")
    return tuple(sorted(set(lines)))


def compile_policy(
    sources: list[Path],
    output: Path,
    manifest: Path,
    ruleset: str,
    allowlist: Path | None = None,
    endpoint_sources: list[Path] | None = None,
    endpoint_output: Path | None = None,
    min_rules: int = 1,
    max_rules: int = 2_500_000,
    stamp: str | None = None,
) -> ProviderResult:
    endpoint_sources = endpoint_sources or []
    if endpoint_sources and endpoint_output is None:
        raise ValueError("endpoint_output is required when endpoint sources are provided")
    allow = parse_allowlist(allowlist.read_text(encoding="utf-8") if allowlist else "")
    domains: set[str] = set()
    unsupported = 0
    source_digests: list[tuple[str, str]] = []
    for source in sources:
        data = source.read_text(encoding="utf-8")
        result = parse_provider(data, allow)
        domains.update(result.domains)
        unsupported += result.unsupported
        source_digests.append((source.name, hashlib.sha256(data.encode("utf-8")).hexdigest()))
    if not min_rules <= len(domains) <= max_rules:
        raise ValueError(f"refusing suspicious ruleset with {len(domains)} entries")
    endpoint_lines: tuple[str, ...] = ()
    for source in endpoint_sources:
        endpoint_lines += parse_endpoint(source.read_text(encoding="utf-8"))
    endpoint_lines = tuple(sorted(set(endpoint_lines)))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(compile_rules(sorted(domains)))
    if endpoint_output:
        endpoint_output.parent.mkdir(parents=True, exist_ok=True)
        endpoint_output.write_text(
            "format=1\n" + f"ruleset={ruleset}\n" + "\n".join(endpoint_lines) + ("\n" if endpoint_lines else ""),
            encoding="ascii",
            newline="\n",
        )
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    stamp = stamp or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lines = [
        "format=1",
        f"rules={len(domains)}",
        f"ruleset={ruleset}",
        f"sha256={digest}",
        f"compiler={COMPILER_VERSION}",
        f"compiled_at={stamp}",
        f"unsupported_rule_count={unsupported}",
        f"endpoint_count={len(endpoint_lines)}",
        "sources=" + ",".join(name for name, _ in source_digests),
    ]
    if endpoint_output:
        # Bind endpoint bytes to the same manifest as rules.bin. Compiler
        # generations must pass the daemon's digest validation before publish.
        lines.append(f"endpoint_sha256={hashlib.sha256(endpoint_output.read_bytes()).hexdigest()}")
    for name, source_digest in source_digests:
        lines.append(f"source_{name}_sha256={source_digest}")
        if name in SOURCE_URLS:
            lines.append(f"source_{name}={SOURCE_URLS[name]}")
    if len(source_digests) == 1:
        provider_digest = source_digests[0][1]
    else:
        provider_hasher = hashlib.sha256()
        for name, source_digest in source_digests:
            provider_hasher.update(name.encode("utf-8"))
            provider_hasher.update(b"=")
            provider_hasher.update(source_digest.encode("ascii"))
            provider_hasher.update(b"\n")
        provider_digest = provider_hasher.hexdigest()
    lines.append(f"provider_sha256={provider_digest}")
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    return ProviderResult(tuple(sorted(domains)), unsupported, endpoint_lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--endpoint-source", action="append", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--endpoint-output", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--ruleset", required=True)
    parser.add_argument("--min-rules", type=int, default=1)
    parser.add_argument("--max-rules", type=int, default=2_500_000)
    args = parser.parse_args()
    result = compile_policy(
        args.source,
        args.output,
        args.manifest,
        args.ruleset,
        args.allowlist,
        args.endpoint_source,
        args.endpoint_output,
        args.min_rules,
        args.max_rules,
    )
    print(f"compiled rules={len(result.domains)} unsupported={result.unsupported} endpoints={len(result.endpoint_lines)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
