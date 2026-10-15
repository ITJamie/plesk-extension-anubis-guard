import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/sbin"))
import ag_payload
import ag_runtime


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.module = self.root / "module"
        self.module.mkdir()
        self.archive = self.root / "fixture.tar.gz"
        with tarfile.open(self.archive, "w:gz") as tar:
            for name, data in (("anubis/bin/anubis", b"fixture binary"), ("anubis/LICENSE", b"fixture license")):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        self.lock = {"version": "1.28.1", "sha256": ag_payload.digest(self.archive),
                     "url": "https://github.com/TecharoHQ/anubis/releases/download/v1.28.1/anubis-1.28.1-linux-amd64.tar.gz"}

    def tearDown(self):
        self.temp.cleanup()

    def response(self):
        return io.BytesIO(self.archive.read_bytes())

    def test_download_then_reuse_verified_cache_without_network(self):
        with patch.object(ag_payload, "release_open", return_value=self.response()) as fetch:
            binary = ag_payload.acquire(self.root / "cache", self.module, self.lock)
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(binary.read_bytes(), b"fixture binary")
        with patch.object(ag_payload, "release_open", side_effect=AssertionError("must not download cached runtime")):
            self.assertEqual(ag_payload.acquire(self.root / "cache", self.module, self.lock), binary)
        self.assertEqual((binary.parent.parent / "LICENSE").read_bytes(), b"fixture license")

    def test_hash_mismatch_does_not_publish_or_unpack_runtime(self):
        lock = {**self.lock, "sha256": "a" * 64}
        with patch.object(ag_payload, "release_open", return_value=self.response()):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                ag_payload.acquire(self.root / "cache", self.module, lock)
        self.assertFalse((self.root / "cache/1.28.1").exists())
        self.assertEqual(list((self.root / "cache").iterdir()), [])

    def test_download_error_leaves_no_cache_entry(self):
        with patch.object(ag_payload, "release_open", side_effect=OSError("offline")):
            with self.assertRaisesRegex(OSError, "offline"):
                ag_payload.acquire(self.root / "cache", self.module, self.lock)
        self.assertEqual(list((self.root / "cache").iterdir()), [])

    def test_offline_bundle_uses_same_verification_without_network(self):
        runtime = self.module / "runtime"
        ag_payload.extract_runtime(self.archive, runtime, self.lock["sha256"])
        (self.module / "runtime-manifest.json").write_text(json.dumps(ag_payload.manifest(runtime, self.lock)))
        with patch.object(ag_payload, "release_open", side_effect=AssertionError("offline bundle must not download")):
            binary = ag_payload.acquire(self.root / "cache", self.module, self.lock)
        self.assertEqual(binary.read_bytes(), b"fixture binary")

    def test_corrupted_cache_is_rejected(self):
        with patch.object(ag_payload, "release_open", return_value=self.response()):
            binary = ag_payload.acquire(self.root / "cache", self.module, self.lock)
        binary.write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            ag_payload.acquire(self.root / "cache", self.module, self.lock)

    def test_unpinned_url_rejected_before_network_access(self):
        with patch.object(ag_payload, "release_open", side_effect=AssertionError("must reject first")):
            with self.assertRaisesRegex(ValueError, "pinned"):
                ag_payload.download({**self.lock, "url": "https://example.test/latest"}, self.root / "out")

    def test_oversized_download_is_rejected(self):
        with patch.object(ag_payload, "MAX_ARCHIVE", 2), patch.object(ag_payload, "release_open", return_value=self.response()):
            with self.assertRaisesRegex(ValueError, "limit"):
                ag_payload.download(self.lock, self.root / "out")

    def test_acquisition_failure_precedes_service_or_routing_changes(self):
        (self.module / "runtime.lock.json").write_text(json.dumps(self.lock))
        with patch.object(ag_runtime, "ROOT", self.root / "state"), patch.object(ag_runtime, "MODULE", self.module), \
                patch.object(ag_runtime, "preflight"), patch.object(ag_runtime, "execute") as command, \
                patch.object(ag_runtime, "acquire", side_effect=OSError("network failure")):
            with self.assertRaisesRegex(OSError, "network failure"):
                ag_runtime.install()
            command.assert_not_called()
        self.assertFalse((self.root / "state/state.json").exists())

    def test_pinned_offline_bundle_does_not_shadow_a_different_release_download(self):
        runtime = self.module / "runtime"
        ag_payload.extract_runtime(self.archive, runtime, self.lock["sha256"])
        (self.module / "runtime-manifest.json").write_text(json.dumps(ag_payload.manifest(runtime, self.lock)))
        override = {**self.lock, "version": "1.29.0", "url": self.lock["url"].replace('1.28.1', '1.29.0')}
        with patch.object(ag_payload, "release_open", return_value=self.response()) as fetch:
            binary = ag_payload.acquire(self.root / "cache", self.module, override)
        self.assertEqual(binary.parent.parent.name, "1.29.0")
        self.assertEqual(fetch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
