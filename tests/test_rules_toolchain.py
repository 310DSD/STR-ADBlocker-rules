from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from build_cloud_generation import DEFAULT_SOURCES, GENERATION_FILES, build_cloud_generation  # noqa: E402


class RulesToolchainTests(unittest.TestCase):
    def test_production_source_set_is_six_and_generation_has_no_hotset(self) -> None:
        self.assertEqual(len(DEFAULT_SOURCES), 6)
        self.assertNotIn("hotset.hosts", GENERATION_FILES)
        self.assertNotIn("hotset.domains", GENERATION_FILES)
        self.assertIn("categories.bin", GENERATION_FILES)

    def test_parallel_build_emits_quality_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "provider.txt"
            source.write_text("||ads.example^\n||track.example^\n", encoding="ascii")
            work = root / "work"
            out = root / "out"
            report_path = out / "quality-report.json"
            latest = build_cloud_generation(
                work,
                out,
                [("provider", source.as_uri())],
                endpoint_raw_url=None,
                stamp="toolchain-test",
                min_rules=1,
                sensitive_min_sources=1,
                max_rules=10_000,
                jobs=2,
                quality_report=report_path,
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], 1)
            self.assertEqual(report["token"], "toolchain-test")
            self.assertEqual(report["rules"], latest["rules"])
            self.assertEqual(report["sources"]["provider"]["domains"], 2)
            self.assertEqual(report["archive_sha256"], latest["archive_sha256"])


if __name__ == "__main__":
    unittest.main()
