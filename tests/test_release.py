"""Check release gates and the actual packages without contacting GitHub."""
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "tools"))
import metadata
import release
from build import digest


class ReleaseTests(unittest.TestCase):
    def test_release_tag_must_exactly_match_metadata(self):
        current = metadata.version()
        self.assertEqual(metadata.version(tag="v" + current), current)
        for tag in (current, "v999.0.0", "v" + current + "-rc1", "v" + current + "/bad"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "match metadata"):
                metadata.version(tag=tag)

    def test_notes_include_only_requested_version(self):
        changelog = "# Changelog\n\n## 1.2.3 — release\n\n- Current change.\n\n## 1.2.2 — earlier\n\n- Old change.\n"
        self.assertEqual(release.notes("1.2.3", changelog), "- Current change.\n")
        self.assertEqual(release.notes("1.2.2", changelog), "- Old change.\n")
        for version, body in (("9.0.0", changelog), ("1.2.3", "## 1.2.3\n\n## 1.2.2\n- Earlier\n")):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.notes(version, body)

    def test_wrong_tag_produces_no_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                release.prepare("v999.0.0", temp)
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_release_assets_include_license_notes_and_valid_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            assets = release.prepare("v" + metadata.version(), temp)
            self.assertEqual(len(assets), 2)
            for asset in assets:
                self.assertEqual(asset.with_suffix(".zip.sha256").read_text(), digest(asset) + "  " + asset.name + "\n")
                with zipfile.ZipFile(asset) as package:
                    self.assertIsNone(package.testzip())
                    self.assertEqual(package.read("LICENSE"), (BASE / "LICENSE").read_bytes())
            self.assertIn("not installable", (Path(temp) / "release-notes.md").read_text())
            with zipfile.ZipFile(assets[1]) as package:
                self.assertIn(".github/workflows/ci.yml", package.namelist())

    def test_metadata_rejects_missing_duplicate_and_invalid_fields(self):
        original = (BASE / "src/meta.xml").read_text()
        current = metadata.version()
        invalid = [original.replace('<id>anubis-guard</id>', ''),
                   original.replace('</module>', '<id>anubis-guard</id></module>'),
                   original.replace('<release>1</release>', '<release>0</release>'),
                   original.replace('<version>' + current, '<version>01.2.3'),
                   original.replace('<os>unix</os>', '<os>windows</os>')]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "meta.xml"
            for content in invalid:
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(ValueError):
                    metadata.version(path)


if __name__ == "__main__":
    unittest.main()
