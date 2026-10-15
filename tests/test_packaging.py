import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build", BASE / "tools/build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class PackagingTests(unittest.TestCase):
    def test_source_archive_is_reproducible_and_contains_frontend(self):
        with tempfile.TemporaryDirectory() as temp:
            path = build.build(source_only=True, output_dir=temp)
            before = path.read_bytes()
            build.build(source_only=True, output_dir=temp)
            self.assertEqual(path.read_bytes(), before)
            with zipfile.ZipFile(path) as package:
                self.assertEqual(package.read("LICENSE"), (BASE / "LICENSE").read_bytes())
                self.assertIn("src/htdocs/dist/app.js", package.namelist())
                self.assertIn("tests/test_core.py", package.namelist())
                self.assertFalse(any("__pycache__" in n or n.startswith("dist/") for n in package.namelist()))

    def test_default_installer_defers_pinned_download_until_install(self):
        with tempfile.TemporaryDirectory() as temp:
            path = build.build(output_dir=temp)
            with zipfile.ZipFile(path) as package:
                self.assertEqual(package.read("LICENSE"), (BASE / "LICENSE").read_bytes())
                self.assertIn("sbin/runtime.lock.json", package.namelist())
                self.assertIn("sbin/ag_payload.py", package.namelist())
                self.assertIn("sbin/ag_geoip.py", package.namelist())
                self.assertIn("sbin/ag_versions.py", package.namelist())
                self.assertIn("docs/runtime-versions.md", package.namelist())
                self.assertEqual(package.getinfo("sbin/anubis-launch").external_attr >> 16 & 0o777, 0o755)
                self.assertIn("sbin/data/default-rules.json", package.namelist())
                self.assertIn("sbin/data/rules-provenance.json", package.namelist())
                self.assertIn("docs/geoip.md", package.namelist())
                for name in ("happy", "pensive", "reject"):
                    data = package.read(f"sbin/assets/generic-v1/{name}.webp")
                    self.assertEqual(data[:4], b"RIFF")
                    self.assertEqual(data[8:12], b"WEBP")
                    self.assertIn(f"sbin/assets/generic-v1/{name}.svg", package.namelist())
                self.assertFalse(any(name.endswith(".mmdb") or name.endswith("credentials.json") for name in package.namelist()))
                self.assertNotIn("sbin/runtime/bin/anubis", package.namelist())
                self.assertEqual(package.getinfo("sbin/anubis-guard").external_attr >> 16 & 0o777, 0o755)

    def archive(self, root, entries):
        path = root / "runtime.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, body in entries:
                member = tarfile.TarInfo(name)
                member.size = len(body)
                tar.addfile(member, io.BytesIO(body))
        return path

    def test_runtime_archive_integrity_is_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.archive(root, [("anubis/bin/anubis", b"test")])
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                build.extract_runtime(path, root / "out", "a" * 64)

    def test_runtime_extraction_retains_notices_and_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.archive(root, [("anubis-1.28.1/bin/anubis", b"test"), ("anubis-1.28.1/LICENSE", b"license")])
            build.extract_runtime(path, root / "out", build.digest(path))
            self.assertTrue((root / "out/bin/anubis").stat().st_mode & 0o100)
            self.assertEqual((root / "out/LICENSE").read_text(), "license")

    def test_archive_traversal_and_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.archive(root, [("bin/anubis", b"test"), ("../escape", b"bad")])
            with self.assertRaisesRegex(ValueError, "unsafe"):
                build.extract_runtime(path, root / "out", build.digest(path))
            self.assertFalse((root / "escape").exists())


if __name__ == "__main__":
    unittest.main()
