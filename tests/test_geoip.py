"""Real MMDB metadata fixtures plus isolated download/activation boundaries."""
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/sbin"))
import ag_geoip
from ag_core import GuardError, policy
from ag_runtime import Runtime, atomic
from test_runtime import FakeRuntime


def mmdb(path, kind="country", epoch=1700000000):
    """Original empty MMDB fixture with valid metadata; no licensed IP data."""
    def text(value):
        body = value.encode()
        return bytes([64 + len(body)]) + body
    def uint(value, bits):
        size = max(1, (value.bit_length() + 7) // 8)
        header = bytes([(5 if bits == 16 else 6) * 32 + size]) if bits != 64 else bytes([size, 2])
        return header + value.to_bytes(size, "big")
    entries = {"node_count": uint(1, 32), "record_size": uint(24, 16), "ip_version": uint(4, 16),
               "database_type": text(ag_geoip.KINDS[kind]), "languages": b"\x01\x04" + text("en"),
               "binary_format_major_version": uint(2, 16), "binary_format_minor_version": uint(0, 16),
               "build_epoch": uint(epoch, 64), "description": b"\xe1" + text("en") + text("Original test fixture")}
    metadata = bytes([224 + len(entries)]) + b"".join(text(k) + v for k, v in entries.items())
    path.write_bytes(b"\x00\x00\x01" * 2 + b"\x00" * 16 + b"\xab\xcd\xefMaxMind.com" + metadata)
    return path


class ConfigurationTests(unittest.TestCase):
    def test_sources_and_secret_retention(self):
        config, credentials = ag_geoip.configuration({"mode": "maxmind", "account_id": "123", "license_key": ""}, {"license_key": "secret"})
        self.assertEqual(config, {"mode": "maxmind", "account_id": "123"})
        self.assertEqual(credentials, {"license_key": "secret"})
        self.assertEqual(ag_geoip.configuration({"mode": "disabled", "clear_key": True}, credentials)[1], {})
        self.assertNotIn("license_key", config)

    def test_invalid_config_and_patterns(self):
        for payload in ({}, {"mode": []}, {"mode": "maxmind", "account_id": "123"},
                        {"mode": "maxmind", "account_id": "0", "license_key": "abc"},
                        {"mode": "disabled", "license_key": "a\nb"}, {"mode": "disabled", "clear_key": "true"},
                        {"mode": "disabled", "clear_key": True, "license_key": "abc"},
                        {"mode": "disabled", "command": "id"}):
            with self.subTest(payload=payload), self.assertRaises(GuardError):
                ag_geoip.configuration(payload, {})
        for pattern in ("relative.mmdb", "/db/**/Country.mmdb", "/db/../x", "/db/?ountry.mmdb", "/db/[ab].mmdb", "/db/", "/db/\nx"):
            with self.subTest(pattern=pattern), self.assertRaises(GuardError):
                ag_geoip.configuration({"mode": "local", "country_path": pattern, "asn_path": "/db/asn.mmdb"}, {})

    def test_disabled_rules_omit_entire_dependent_rules_without_altering_others(self):
        disabled = policy({"enabled": True}, "/db", "/metrics")
        enabled = policy({"enabled": True}, "/db", "/metrics", {"country": "/c.mmdb", "asn": "/a.mmdb"})
        self.assertEqual(disabled["bots"], [r for r in enabled["bots"] if not ({"asns", "geoip"} & set(r))])
        self.assertEqual(len(enabled["bots"]) - len(disabled["bots"]), 2)
        self.assertNotIn("geoip", disabled)
        self.assertEqual(enabled["geoip"]["asn"], {"path": "/a.mmdb"})


@unittest.skipUnless(shutil.which("mmdblookup"), "native MaxMind validator unavailable")
class SelectionTests(unittest.TestCase):
    def test_native_metadata_and_newest_build_not_mtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old = mmdb(root / "old.mmdb", epoch=1600000000)
            new = mmdb(root / "new.mmdb", epoch=1700000000)
            os.utime(old, (time.time(), time.time()))
            os.utime(new, (100, 100))
            (root / "invalid.mmdb").write_bytes(b"junk")
            mmdb(root / "wrong.mmdb", "asn", epoch=1800000000)
            selected, metadata, warnings = ag_geoip.select_database(str(root / "*.mmdb"), "country")
            self.assertEqual(selected, new)
            self.assertEqual(metadata["build_epoch"], 1700000000)
            self.assertEqual(len(warnings), 2)

    def test_folder_patterns_ties_and_wrong_type(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("a", "b"):
                (root / name).mkdir()
                mmdb(root / name / "country.mmdb")
            selected, _, _ = ag_geoip.select_database(str(root / "*" / "country.mmdb"), "country")
            self.assertEqual(selected, root / "b/country.mmdb")
            with self.assertRaises(GuardError):
                ag_geoip.select_database(str(root / "*" / "country.mmdb"), "asn")
            with self.assertRaises(GuardError):
                ag_geoip.select_database(str(root / "missing*"), "country")

    def test_candidate_count_and_file_size_bounds(self):
        with patch.object(ag_geoip.glob, "iglob", return_value=iter(["/bad"] * 1001)):
            with self.assertRaisesRegex(GuardError, "1000"):
                ag_geoip.select_database("/bad*", "country")
        with tempfile.TemporaryDirectory() as temp:
            p = mmdb(Path(temp) / "c.mmdb")
            with patch.object(ag_geoip, "MAX_FILE", 1), self.assertRaises(GuardError):
                ag_geoip.inspect_database(p, "country")


class DownloadTests(unittest.TestCase):
    def archive(self, name, body=b"fixture", type=tarfile.REGTYPE):
        result = io.BytesIO()
        with tarfile.open(fileobj=result, mode="w:gz") as bundle:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            member.type = type
            bundle.addfile(member, io.BytesIO(body) if type == tarfile.REGTYPE else None)
        return result.getvalue()

    def test_download_auth_and_safe_extract(self):
        opener = Mock()
        opener.open.return_value = io.BytesIO(self.archive("GeoLite2-Country_20261015/GeoLite2-Country.mmdb"))
        with tempfile.TemporaryDirectory() as temp, patch.object(ag_geoip.urllib.request, "build_opener", return_value=opener):
            path = ag_geoip.download_database("country", "123", "secret", Path(temp))
            self.assertEqual(path.read_bytes(), b"fixture")
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz")
            self.assertEqual(request.get_header("Authorization"), "Basic MTIzOnNlY3JldA==")

    def test_reject_archive_traversal_symlinks_and_size(self):
        for body in (self.archive("../GeoLite2-Country.mmdb"), self.archive("GeoLite2-Country.mmdb", type=tarfile.SYMTYPE), b"not a tar"):
            opener = Mock()
            opener.open.return_value = io.BytesIO(body)
            with tempfile.TemporaryDirectory() as temp, patch.object(ag_geoip.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(GuardError):
                    ag_geoip.download_database("country", "123", "secret", Path(temp))
        opener.open.return_value = io.BytesIO(b"0123456789")
        with tempfile.TemporaryDirectory() as temp, patch.object(ag_geoip.urllib.request, "build_opener", return_value=opener), patch.object(ag_geoip, "MAX_FILE", 1):
            with self.assertRaisesRegex(GuardError, "size or time"):
                ag_geoip.download_database("country", "123", "secret", Path(temp))

    def test_http_errors_and_redirect_secrets(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError("https://example/?secret", 401, "secret", {}, None)
        with tempfile.TemporaryDirectory() as temp, patch.object(ag_geoip.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(GuardError) as raised:
                ag_geoip.download_database("country", "123", "secret", Path(temp))
        self.assertIn("HTTP 401", str(raised.exception))
        self.assertNotIn("secret", str(raised.exception))
        handler = ag_geoip.SafeRedirect()
        req = urllib.request.Request("https://download.maxmind.com/db", headers={"Authorization": "secret"})
        redirected = handler.redirect_request(req, None, 302, "", {}, "https://" + ag_geoip.R2_HOST + "/signed")
        self.assertIsNone(redirected.get_header("Authorization"))
        for target in ("http://download.maxmind.com/db", "https://evil.example/db", "https://user@download.maxmind.com/db"):
            with self.subTest(target=target), self.assertRaises(GuardError):
                handler.redirect_request(req, None, 302, "", {}, target)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.runtime = FakeRuntime(self.root)
        self.geo = ag_geoip.GeoIP(self.runtime)
        self.geo.initialize()
        self.patches = [patch('ag_runtime.ROOT', self.root), patch.object(ag_geoip.os, "chown"),
                        patch.object(ag_geoip, "execute", return_value="")]
        for p in self.patches:
            p.start()
        self.runtime.write({"version": 1, "domains": {"7": {"enabled": True, "paths": [], "ips": [], "name": "example.test", "origin_key": "a" * 64}}})
        self.source = self.root / "sources"
        self.source.mkdir()
        self.config = {"mode": "local", "country_path": str(self.source / "country*.mmdb"), "asn_path": str(self.source / "asn*.mmdb")}
        self.credentials = {"license_key": "sensitive-test-key"}
        mmdb(self.source / "country.mmdb")
        mmdb(self.source / "asn.mmdb", "asn")

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def run_job(self, config=None):
        self.geo.enqueue(config if config is not None else self.config)
        self.assertTrue(self.geo.worker()["ok"])

    def test_snapshot_activation_redaction_and_unchanged_no_restart(self):
        self.run_job({**self.config, "license_key": self.credentials["license_key"]})
        state = self.geo.state()
        self.assertEqual(state["active"]["country"]["build_epoch"], 1700000000)
        self.assertEqual([c[0] for c in self.runtime.calls], ["prepare", "start"])
        self.assertNotIn(self.credentials["license_key"], json.dumps(self.geo.status()))
        self.assertNotIn(self.credentials["license_key"], self.geo.job_path.read_text())
        self.assertEqual(self.geo.secret_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(self.geo.paths()["country"]).stat().st_mode & 0o777, 0o640)
        self.runtime.calls.clear()
        self.geo.enqueue()
        self.assertTrue(self.geo.worker()["ok"])
        self.assertEqual(self.runtime.calls, [])

    def test_source_removed_or_invalid_refresh_retains_working_snapshot(self):
        self.run_job()
        before = self.geo.paths()
        for path in self.source.iterdir():
            path.unlink()
        self.geo.enqueue()
        self.assertFalse(self.geo.worker()["ok"])
        self.assertEqual(self.geo.paths(), before)
        self.assertTrue(all(Path(p).exists() for p in before.values()))

    def test_activation_failure_restores_previous_generation(self):
        self.run_job()
        before = self.geo.paths()
        mmdb(self.source / "country-new.mmdb", epoch=1750000000)
        self.runtime.fail = "start"
        self.geo.enqueue()
        self.assertFalse(self.geo.worker()["ok"])
        self.assertEqual(self.geo.paths(), before)
        self.assertFalse(self.geo.pending.exists())
        self.assertIn("restored", self.geo.status()["job"]["error"])

    def test_failed_rollback_keeps_journal_and_blocks_site_saves(self):
        self.run_job()
        mmdb(self.source / "country-new.mmdb", epoch=1750000000)
        self.runtime.start = Mock(side_effect=GuardError("service failure"))
        self.geo.enqueue()
        self.assertFalse(self.geo.worker()["ok"])
        self.assertTrue(self.geo.pending.exists())
        with self.assertRaisesRegex(GuardError, "recovery"):
            self.runtime.apply("7", {"enabled": True})
        self.runtime.start = Mock()
        with self.runtime.locked():
            self.geo.recover()
        self.assertFalse(self.geo.pending.exists())

    def test_crash_recovery_and_secret_restore(self):
        self.run_job({**self.config, "license_key": "old-key"})
        previous = self.geo.state()
        atomic(self.geo.pending, json.dumps({"previous": previous, "credentials": {"license_key": "old-key"}, "affected": ["7"]}))
        atomic(self.geo.state_path, json.dumps({**previous, "active": None}))
        with self.runtime.locked():
            self.geo.recover()
        self.assertEqual(self.geo.state(), previous)
        self.assertEqual(json.loads(self.geo.secret_path.read_text()), {"license_key": "old-key"})

    def test_scheduling_uses_daily_managed_and_five_minute_local_intervals(self):
        self.run_job()
        self.runtime.calls.clear()
        with patch.object(self.geo, "snapshot", wraps=self.geo.snapshot) as snapshot:
            self.geo.worker()
            snapshot.assert_not_called()
            state = self.geo.state()
            state["last_check"] = int(time.time()) - 301
            atomic(self.geo.state_path, json.dumps(state))
            self.geo.worker()
            snapshot.assert_called_once()
        state = self.geo.state()
        state["config"] = {"mode": "maxmind", "account_id": "123"}
        state["last_check"] = int(time.time()) - 3600
        atomic(self.geo.state_path, json.dumps(state))
        with patch.object(self.geo, "snapshot") as snapshot:
            self.geo.worker()
            snapshot.assert_not_called()

    def test_jobs_serialize_and_do_not_publish_credentials_in_status(self):
        self.geo.enqueue({**self.config, "license_key": "queued-secret"})
        self.assertNotIn("queued-secret", json.dumps(self.geo.status()))
        with self.assertRaisesRegex(GuardError, "queued"):
            self.geo.enqueue()
        with self.geo.jobs_locked(), self.assertRaisesRegex(GuardError, "already running"):
            self.geo.enqueue()

    def test_disabling_clears_rules_and_explicitly_removes_credentials(self):
        self.run_job({**self.config, "license_key": "old-key"})
        self.run_job({"mode": "disabled", "clear_key": True})
        self.assertIsNone(self.geo.paths())
        self.assertFalse(self.geo.status()["has_license_key"])
        self.assertFalse(self.geo.pending.exists())

    def test_runtime_policy_uses_shared_paths_then_removes_dependent_rules(self):
        self.run_job()
        config = self.runtime.read()["domains"]["7"]
        with patch('ag_runtime.RUN', self.root / "run"):
            Runtime.prepare(self.runtime, "7", config)
            generated = json.loads((self.root / "7/policy.json").read_text())
            self.assertEqual(generated["geoip"]["country"]["path"], self.geo.paths()["country"])
            self.assertTrue(any("asns" in rule for rule in generated["bots"]))
            self.run_job({"mode": "disabled"})
            Runtime.prepare(self.runtime, "7", config)
            generated = json.loads((self.root / "7/policy.json").read_text())
            self.assertNotIn("geoip", generated)
            self.assertFalse(any("asns" in rule or "geoip" in rule for rule in generated["bots"]))

    def test_refresh_changed_pair_uses_no_web_server_commands(self):
        self.run_job()
        mmdb(self.source / "asn-new.mmdb", "asn", epoch=1750000000)
        with patch.object(ag_geoip, "execute") as command:
            self.geo.enqueue()
            self.geo.worker()
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ["/usr/bin/systemctl", "start", "--no-block", "plesk-anubis-geoip.service"]])
        self.assertFalse(any(call[0] in ("routing", "reconfigure") for call in self.runtime.calls))

    def test_retains_only_active_and_previous_generations(self):
        self.run_job()
        first = Path(self.geo.paths()["country"]).parent
        mmdb(self.source / "country.mmdb", epoch=1710000000)
        self.geo.enqueue(); self.geo.worker()
        second = Path(self.geo.paths()["country"]).parent
        self.assertTrue(first.exists())
        mmdb(self.source / "country.mmdb", epoch=1720000000)
        self.geo.enqueue(); self.geo.worker()
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())
        self.assertTrue(Path(self.geo.paths()["country"]).exists())
