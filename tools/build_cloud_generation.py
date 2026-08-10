#!/usr/bin/env python3
"""Build a validated, publishable cloud rules generation from provider sources.

This module only orchestrates: it downloads the provider sources, reuses the
production compilers (compile_policy, compile_hotset, compile_ip_feed),
validates the result, and packages an immutable generation tarball plus
latest.json. It never changes the binary format or endpoint semantics.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    from .compile_policy import compile_policy
    from .compile_hotset import compile_hotset
    from .compile_ip_feed import parse_networks, render as render_endpoints
except ImportError:  # Script execution from tools/ keeps the original CLI.
    from compile_policy import compile_policy
    from compile_hotset import compile_hotset
    from compile_ip_feed import parse_networks, render as render_endpoints

SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ENDPOINT_TTL = 86_400
HAGEZI_NORMAL_PRIMARY = "https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/adblock/multi.txt"
HAGEZI_NORMAL_GITLAB = "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/adblock/multi.txt"
HAGEZI_NORMAL_OLD_GITHUB = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt"

SOURCE_FALLBACKS = {
    HAGEZI_NORMAL_PRIMARY: (HAGEZI_NORMAL_GITLAB,),
    HAGEZI_NORMAL_OLD_GITHUB: (HAGEZI_NORMAL_PRIMARY, HAGEZI_NORMAL_GITLAB),
}

DEFAULT_SOURCES = (
    f"hagezi-normal={HAGEZI_NORMAL_PRIMARY}",
    "antiad-easylist=https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt",
    "1hosts-lite=https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt",
    "adguard-dns=https://filters.adtidy.org/extension/chromium/filters/15.txt",
    "adguard-base=https://filters.adtidy.org/extension/chromium/filters/2.txt",
    "adguard-chinese=https://filters.adtidy.org/extension/chromium/filters/224.txt",
    "banad=https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "oisd-big=https://big.oisd.nl",
)

DEFAULT_ENDPOINT_RAW = (
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Advertising/Advertising.list"
)

GENERATION_FILES = (
    "endpoints.txt",
    "generation.sig",
    "hotset.domains",
    "hotset.hosts",
    "hotset.manifest",
    "manifest",
    "rules.bin",
)


def parse_source(value: str) -> tuple[str, str]:
    name, separator, url = value.partition("=")
    if not separator or not SOURCE_RE.fullmatch(name) or not (
        url.startswith("https://") or url.startswith("file://")
    ):
        raise argparse.ArgumentTypeError("source must be name=https://url or name=file://path")
    return name, url


def fetch(url: str, attempts: int = 4, timeout: int = 180) -> bytes:
    """Download with bounded retries. file:// is accepted for offline tests."""
    last_error: Exception | None = None
    candidates = (url, *SOURCE_FALLBACKS.get(url, ()))
    for candidate in candidates:
        for attempt in range(attempts):
            try:
                request = urllib.request.Request(candidate, headers={"User-Agent": "STR-AdBlocker-rules/0.5"})
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    return response.read()
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                last_error = error
                if isinstance(error, urllib.error.HTTPError) and error.code == 404:
                    break
                if attempt + 1 < attempts:
                    time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"download failed after {attempts} attempts: {url}: {last_error}")


def read_manifest(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _openssl_sign(message: bytes, private_key_pem: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        key_path = root / "key.pem"
        message_path = root / "message.bin"
        signature_path = root / "signature.bin"
        key_path.write_bytes(private_key_pem)
        message_path.write_bytes(message)
        subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-rawin",
                "-inkey", str(key_path),
                "-in", str(message_path),
                "-out", str(signature_path),
            ],
            check=True,
            capture_output=True,
        )
        return signature_path.read_bytes()


def sign_generation(gen: Path, private_key_pem: bytes) -> str:
    """Sign the generation manifest with an Ed25519 private key.

    The signature covers the ASCII hex of the manifest sha256, matching the
    module-side `fetch verify-gen` verifier. `generation.sig` is written into
    the generation directory and packaged with the archive.
    """
    manifest = (gen / "manifest").read_bytes()
    message = hashlib.sha256(manifest).hexdigest().encode("ascii")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("STR_GENERATION_SIGNING_KEY is not an Ed25519 private key")
        signature = key.sign(message)
    except ImportError:
        signature = _openssl_sign(message, private_key_pem)
    hex_signature = signature.hex()
    (gen / "generation.sig").write_text(hex_signature + "\n", encoding="ascii")
    return hex_signature


def package_generation(gen: Path, output: Path) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(str(output) + ".new")
    with open(temporary, "wb") as raw:
        # Pin the gzip header timestamp too; tarfile's "w:gz" mode embeds the
        # current time, which makes otherwise identical generations differ
        # across a second boundary and breaks reproducibility.
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name in sorted(GENERATION_FILES):
                    source = gen / name
                    if not source.is_file():
                        continue
                    info = archive.gettarinfo(str(source), arcname=name)
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mode = 0o644
                    with source.open("rb") as handle:
                        archive.addfile(info, handle)
    temporary.replace(output)
    return sha256_bytes(output.read_bytes())


def build_cloud_generation(
    work: Path,
    output: Path,
    sources: list[tuple[str, str]],
    endpoint_raw_url: str | None = DEFAULT_ENDPOINT_RAW,
    allowlist: Path | None = None,
    stamp: str | None = None,
    min_rules: int = 300_000,
    max_rules: int = 2_500_000,
) -> dict[str, object]:
    if not sources:
        sources = [parse_source(item) for item in DEFAULT_SOURCES]
    labels = [name for name, _ in sources]
    if len(set(labels)) != len(labels):
        raise ValueError("source names must be unique")

    work.mkdir(parents=True, exist_ok=True)
    source_dir = work / "sources"
    source_dir.mkdir(exist_ok=True)
    gen = work / "generation"
    if gen.exists():
        for child in gen.iterdir():
            if child.is_dir():
                raise ValueError(f"refusing dirty generation work dir: {child}")
    gen.mkdir(exist_ok=True)

    stamp = stamp or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[0-9A-Za-z._-]+", stamp):
        raise ValueError("stamp must be a safe ruleset token")

    source_paths: list[Path] = []
    source_digests: dict[str, str] = {}
    for name, url in sources:
        data = fetch(url)
        path = source_dir / name
        path.write_bytes(data)
        source_paths.append(path)
        source_digests[name] = sha256_bytes(data)

    endpoint_sources: list[Path] | None = None
    if endpoint_raw_url:
        endpoint_raw = source_dir / "endpoints.raw"
        endpoint_raw.write_bytes(fetch(endpoint_raw_url))
        networks, rejected = parse_networks(endpoint_raw.read_text(encoding="utf-8", errors="ignore"))
        endpoint_feed = work / "endpoints.feed"
        endpoint_feed.write_text(
            render_endpoints(networks, stamp, ENDPOINT_TTL), encoding="ascii", newline="\n"
        )
        endpoint_sources = [endpoint_feed]
        print(f"endpoint_candidates={len(networks)} rejected={rejected} mode=observe_correlated")

    policy = compile_policy(
        source_paths,
        gen / "rules.bin",
        gen / "manifest",
        stamp,
        stamp=stamp,
        allowlist=allowlist,
        endpoint_sources=endpoint_sources,
        endpoint_output=gen / "endpoints.txt" if endpoint_sources else None,
        min_rules=min_rules,
        max_rules=max_rules,
    )
    hotset_domains = compile_hotset(
        source_paths,
        labels,
        gen / "hotset.hosts",
        gen / "hotset.manifest",
        stamp,
        stamp=stamp,
        allowlist=allowlist,
    )
    (gen / "hotset.domains").write_text(
        "".join(f"{domain}\n" for domain in hotset_domains), encoding="ascii", newline=""
    )

    manifest = read_manifest(gen / "manifest")
    hotset_manifest = read_manifest(gen / "hotset.manifest")
    rules_digest = sha256_bytes((gen / "rules.bin").read_bytes())
    hotset_digest = sha256_bytes((gen / "hotset.hosts").read_bytes())
    endpoint_digest = sha256_bytes((gen / "endpoints.txt").read_bytes()) if endpoint_sources else ""
    if manifest.get("sha256") != rules_digest:
        raise ValueError("rules digest validation failed")
    if hotset_manifest.get("sha256") != hotset_digest:
        raise ValueError("hotset digest validation failed")
    if endpoint_sources and manifest.get("endpoint_sha256") != endpoint_digest:
        raise ValueError("endpoint digest validation failed")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest.get("provider_sha256", "")):
        raise ValueError("provider digest validation failed")
    if int(manifest.get("rules", "0")) != len(policy.domains):
        raise ValueError("rules count mismatch")
    if int(hotset_manifest.get("hotset", "0")) != len(hotset_domains):
        raise ValueError("hotset count mismatch")

    signing_key = os.environ.get("STR_GENERATION_SIGNING_KEY")
    if signing_key:
        sign_generation(gen, signing_key.encode())
    archive_digest = package_generation(gen, output / "generation.tar.gz")
    latest = {
        "token": stamp,
        "published_at": stamp,
        "rules": len(policy.domains),
        "unsupported": policy.unsupported,
        "hotset": len(hotset_domains),
        "endpoints": len(policy.endpoint_lines),
        "rules_sha256": rules_digest,
        "hotset_sha256": hotset_digest,
        "endpoint_sha256": endpoint_digest,
        "provider_sha256": manifest.get("provider_sha256", ""),
        "archive_sha256": archive_digest,
        "endpoint_source": endpoint_raw_url,
        "sources": source_digests,
    }
    (output / "latest.json").write_text(json.dumps(latest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"built token={stamp} rules={latest['rules']} unsupported={latest['unsupported']} "
        f"hotset={latest['hotset']} endpoints={latest['endpoints']} archive={archive_digest}"
    )
    return latest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True, help="scratch directory")
    parser.add_argument("--out", type=Path, required=True, help="output directory for generation.tar.gz and latest.json")
    parser.add_argument("--source", action="append", type=parse_source)
    parser.add_argument("--endpoint-raw-url", default=DEFAULT_ENDPOINT_RAW)
    parser.add_argument("--no-endpoint", action="store_true", help="build without an endpoint sidecar")
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--stamp")
    parser.add_argument("--min-rules", type=int, default=300_000)
    parser.add_argument("--max-rules", type=int, default=2_500_000)
    args = parser.parse_args()
    build_cloud_generation(
        args.work,
        args.out,
        args.source or [],
        None if args.no_endpoint else args.endpoint_raw_url,
        args.allowlist,
        args.stamp,
        args.min_rules,
        args.max_rules,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
