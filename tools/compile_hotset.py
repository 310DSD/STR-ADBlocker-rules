#!/usr/bin/env python3
"""Compile a deterministic hosts hotset from the existing provider parsers.

The hotset is a bounded derived cache. It never replaces the full policy and
does not carry a second allowlist or rule syntax implementation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
from pathlib import Path

try:
    from .compile_hosts import normalize_domain, parse_allowlist
    from .compile_policy import parse_provider
except ImportError:  # Script execution from tools/ keeps the original CLI.
    from compile_hosts import normalize_domain, parse_allowlist
    from compile_policy import parse_provider

COMPILER_VERSION = "str-hotset-1"
MAX_DOMAIN_BYTES = 253


def _valid_hotset_domain(domain: str) -> bool:
    return bool(domain and len(domain.encode("ascii", "ignore")) <= MAX_DOMAIN_BYTES and domain != "localhost")


def choose_hotset(
    source_texts: dict[str, str],
    allowlist: set[str],
    common_limit: int = 20_000,
    antiad_limit: int = 6_000,
    hagezi_limit: int = 4_000,
    maximum: int = 30_000,
) -> tuple[str, ...]:
    parsed: dict[str, set[str]] = {}
    for name, text in source_texts.items():
        parsed[name] = set(parse_provider(text, allowlist).domains)
    if not parsed:
        raise ValueError("hotset requires at least one source")
    if {"hagezi-normal", "antiad-easylist"}.issubset(parsed):
        common = parsed["hagezi-normal"] & parsed["antiad-easylist"]
        antiad_only = parsed["antiad-easylist"] - parsed["hagezi-normal"]
        hagezi_only = parsed["hagezi-normal"] - parsed["antiad-easylist"]
    else:
        common = set()
        antiad_only = set()
        hagezi_only = set().union(*parsed.values())

    def eligible(items: set[str]) -> list[str]:
        return sorted(item for item in items if _valid_hotset_domain(item))

    selected: list[str] = []
    selected.extend(eligible(common)[:common_limit])
    selected.extend(eligible(antiad_only)[:antiad_limit])
    selected.extend(eligible(hagezi_only)[:hagezi_limit])
    if len(selected) < maximum:
        used = set(selected)
        remainder = eligible(set().union(*parsed.values()) - used)
        selected.extend(remainder[: maximum - len(selected)])
    if len(selected) > maximum:
        selected = selected[:maximum]
    if not selected:
        raise ValueError("hotset is empty")
    return tuple(sorted(set(selected)))


def render_hosts(domains: tuple[str, ...], ruleset: str) -> str:
    lines = [
        "# STR AdBlocker hosts hotset",
        f"# ruleset={ruleset}",
        f"# domains={len(domains)}",
        "# Generated from the bundled provider policy; do not edit.",
    ]
    for domain in domains:
        lines.append(f"0.0.0.0 {domain}")
        lines.append(f":: {domain}")
    return "\n".join(lines) + "\n"


def compile_hotset(
    sources: list[Path],
    labels: list[str],
    output: Path,
    manifest: Path,
    ruleset: str,
    allowlist: Path | None = None,
    common_limit: int = 20_000,
    antiad_limit: int = 6_000,
    hagezi_limit: int = 4_000,
    maximum: int = 30_000,
    stamp: str | None = None,
) -> tuple[str, ...]:
    if len(sources) != len(labels) or not labels or len(set(labels)) != len(labels):
        raise ValueError("sources must have unique labels")
    source_texts = {label: source.read_text(encoding="utf-8") for label, source in zip(labels, sources)}
    allow = parse_allowlist(allowlist.read_text(encoding="utf-8") if allowlist else "")
    domains = choose_hotset(source_texts, allow, common_limit, antiad_limit, hagezi_limit, maximum)
    payload = render_hosts(domains, ruleset).encode("ascii")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    stamp = stamp or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    source_digests = [(label, hashlib.sha256(source_texts[label].encode("utf-8")).hexdigest()) for label in labels]
    provider_hasher = hashlib.sha256()
    for label, digest in source_digests:
        provider_hasher.update(f"{label}={digest}\n".encode("ascii"))
    allow_digest = hashlib.sha256((allowlist.read_bytes() if allowlist else b"")).hexdigest()
    lines = [
        "format=1",
        f"hotset={len(domains)}",
        f"ruleset={ruleset}",
        f"sha256={hashlib.sha256(payload).hexdigest()}",
        f"compiler={COMPILER_VERSION}",
        f"compiled_at={stamp}",
        f"common_limit={common_limit}",
        f"antiad_limit={antiad_limit}",
        f"hagezi_limit={hagezi_limit}",
        f"allowlist_sha256={allow_digest}",
        f"provider_sha256={provider_hasher.hexdigest()}",
    ]
    lines.extend(f"source_{label}_sha256={digest}" for label, digest in source_digests)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    return domains


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", type=Path, required=True)
    parser.add_argument("--source-label", action="append", required=True)
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--ruleset", required=True)
    parser.add_argument("--common-limit", type=int, default=20_000)
    parser.add_argument("--antiad-limit", type=int, default=6_000)
    parser.add_argument("--hagezi-limit", type=int, default=4_000)
    parser.add_argument("--max-domains", type=int, default=30_000)
    args = parser.parse_args()
    domains = compile_hotset(
        args.source,
        args.source_label,
        args.output,
        args.manifest,
        args.ruleset,
        args.allowlist,
        args.common_limit,
        args.antiad_limit,
        args.hagezi_limit,
        args.max_domains,
    )
    print(f"compiled hotset={len(domains)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
