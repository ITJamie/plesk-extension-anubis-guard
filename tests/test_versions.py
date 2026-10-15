"""Runtime selection tests use immutable synthetic binaries; no services run."""
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/sbin"))
import ag_payload
import ag_runtime
import ag_versions
from ag_core import GuardError
from ag_runtime import atomic
from test_runtime import FakeRuntime


def release(version="1.29.0"):
    return {"id": 123, "tag_name": "v" + version, "draft": False, "prerelease": False,
            "published_at": "2026-10-15T00:00:00Z", "assets": [{"id": 456, "state": "uploaded",
                "name": f"anubis-{version}-linux-amd64.tar.gz", "digest": "sha256:" + "c" * 64,
                "browser_download_url": f"https://github.com/TecharoHQ/anubis/releases/download/v{version}/anubis-{version}-linux-amd64.tar.gz"}]}


class ReleaseTests(unittest.TestCase):
    def test_official_stable_platform_and_digest_are_required(self):
        valid = release()
        self.assertEqual(ag_versions.release_record(valid)["version"], "1.29.0")
        for key, value in (("draft", True), ("prerelease", True), ("tag_name", "v1.29.0-rc1"), ("tag_name", "../bad")):
            with self.subTest(key=key), self.assertRaises(GuardError):
                ag_versions.release_record({**valid, key: value})
        for key, value in (("digest", None), ("digest", "sha256:wrong"), ("state", "starter"),
                           ("name", "anubis-1.29.0-linux-arm64.tar.gz"), ("browser_download_url", "https://evil.example/runtime")):
            bad = copy.deepcopy(valid); bad["assets"][0][key] = value
            with self.subTest(key=key), self.assertRaises(GuardError):
                ag_versions.release_record(bad)
        for value in (True, None, [], "01.2.3", "1.2.3/../../", "1.2.3;id"):
            with self.subTest(version=value), self.assertRaises(GuardError):
                ag_versions.version_id(value)

    def test_download_redirects_stay_on_official_https_hosts(self):
        handler = ag_payload.ReleaseRedirect()
        request = ag_versions.urllib.request.Request("https://github.com/TecharoHQ/anubis/releases/download/v1.29.0/archive")
        self.assertIsNotNone(handler.redirect_request(request, None, 302, "", {}, "https://release-assets.githubusercontent.com/file"))
        for url in ("http://github.com/file", "https://evil.example/file", "https://user@github.com/file", "https://github.com:444/file"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "", {}, url)


    def test_api_accepts_response_larger_than_previous_two_megabyte_limit(self):
        record = release()
        record["body"] = "x" * (2 * 1024 * 1024)
        response = io.BytesIO(json.dumps([record]).encode())
        response.headers = {"ETag": '"large"'}
        with patch.object(ag_versions.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            data, etag = ag_versions.github("/releases?per_page=10&page=1")
        self.assertEqual(data[0]["tag_name"], "v1.29.0")
        self.assertEqual(etag, '"large"')

    def test_api_response_remains_bounded(self):
        response = io.BytesIO(b" " * (ag_versions.MAX_API_RESPONSE + 1))
        response.headers = {}
        with patch.object(ag_versions.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            with self.assertRaisesRegex(GuardError, "response is too large"):
                ag_versions.github("/releases?per_page=10&page=1")


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.module = self.base / "module"
        self.module.mkdir()
        self.pin = {"version": "1.28.1", "sha256": "a" * 64,
                    "url": "https://github.com/TecharoHQ/anubis/releases/download/v1.28.1/anubis-1.28.1-linux-amd64.tar.gz"}
        (self.module / "runtime.lock.json").write_text(json.dumps(self.pin))
        self.runtime = FakeRuntime(self.base)
        self.patches = [patch.object(ag_runtime, "ROOT", self.base), patch.object(ag_runtime, "MODULE", self.module),
                        patch.object(ag_versions, "execute", return_value=""), patch.object(ag_versions.os, "chown")]
        for patcher in self.patches:
            patcher.start()
        self.manager = ag_versions.Versions(self.runtime)
        self.make_cache(self.pin)
        self.manager.bootstrap()
        self.runtime.write({"version": 1, "domains": {"7": {"enabled": True, "paths": [], "ips": [], "name": "example.test", "origin_key": "a" * 64}}})
        self.future = ag_versions.release_record(release())

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp.cleanup()

    def make_cache(self, record):
        directory = self.base / "runtime" / record["version"]
        (directory / "bin").mkdir(parents=True, exist_ok=True)
        elf = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00"
        (directory / "bin/anubis").write_bytes(elf + record["version"].encode())
        (directory / "bin/anubis").chmod(0o755)
        (directory / ".manifest.json").write_text(json.dumps(ag_payload.manifest(directory, record)))
        (directory / ".release.json").write_text(json.dumps(record))
        return directory / "bin/anubis"

    def test_bootstrap_defaults_to_automatic_and_status_is_dynamic(self):
        self.assertEqual(self.manager.state()["mode"], "automatic")
        self.assertEqual(os.readlink(self.manager.cache / "active"), "1.28.1")
        self.assertEqual(self.manager.status()["downloaded"], ["1.28.1"])
        self.assertEqual((self.manager.cache / "launch").stat().st_mode & 0o777, 0o755)

    def test_download_does_not_activate_and_cache_is_reusable_offline(self):
        def acquire(cache, module, record):
            return self.make_cache(record)
        with patch.object(ag_versions, "github", return_value=(release(), None)), patch.object(ag_versions, "acquire", side_effect=acquire):
            self.manager.download("1.29.0")
        self.assertEqual(self.manager.version(), "1.28.1")
        self.assertEqual(self.runtime.calls, [])
        with patch.object(ag_versions, "github", side_effect=AssertionError("must work offline")):
            self.assertEqual(self.manager.download("1.29.0")["version"], "1.29.0")

    def test_bad_download_and_corrupted_cache_leave_running_version_alone(self):
        with patch.object(ag_versions, "github", return_value=(release(), None)), \
                patch.object(ag_versions, "acquire", side_effect=ValueError("checksum mismatch")):
            with self.assertRaisesRegex(GuardError, "integrity"):
                self.manager.download("1.29.0")
        binary = self.make_cache(self.future)
        binary.write_bytes(b"damaged")
        with self.assertRaisesRegex(GuardError, "integrity"):
            self.manager.activate("override", "1.29.0")
        self.assertEqual(self.manager.version(), "1.28.1")

    def test_catalog_pagination_filtering_etag_and_rate_failure_keep_cache(self):
        prerelease = release("1.30.0"); prerelease["prerelease"] = True
        with patch.object(ag_versions, "github", return_value=([release(), prerelease], '"etag"')) as github:
            self.manager.refresh(1)
        self.assertEqual(self.manager.status()["pages"]["1"]["releases"][0]["version"], "1.29.0")
        self.assertEqual(len(self.manager.status()["pages"]["1"]["releases"]), 1)
        with patch.object(ag_versions, "github", return_value=(None, '"etag"')) as github:
            self.manager.refresh(1)
            github.assert_called_once_with("/releases?per_page=10&page=1", '"etag"')
        before = self.manager.catalog_path.read_bytes()
        with patch.object(ag_versions, "github", side_effect=GuardError("GitHub HTTP 403")):
            with self.assertRaises(GuardError):
                self.manager.refresh(2)
        self.assertEqual(self.manager.catalog_path.read_bytes(), before)

    def test_smaller_pages_keep_pagination_after_filtering_and_reuse_etags(self):
        records = [release("1.29." + str(i)) for i in range(ag_versions.RELEASE_PAGE_SIZE)]
        records[0]["prerelease"] = True
        with patch.object(ag_versions, "github", return_value=(records, '"page-one"')) as request:
            self.manager.refresh(1)
            request.assert_called_once_with("/releases?per_page=10&page=1", None)
        page = self.manager.status()["pages"]["1"]
        self.assertTrue(page["has_more"])
        self.assertEqual(len(page["releases"]), 9)
        with patch.object(ag_versions, "github", return_value=([], '"page-two"')) as request:
            self.manager.refresh(2)
            request.assert_called_once_with("/releases?per_page=10&page=2", None)
        self.assertFalse(self.manager.status()["pages"]["2"]["has_more"])

    def test_pagination_upgrade_replaces_old_etags_only_after_success(self):
        old = {"pages": {"1": {"releases": [], "etag": '"old"', "has_more": True},
                         "2": {"releases": [], "etag": '"old-two"', "has_more": False}}}
        atomic(self.manager.catalog_path, json.dumps(old))
        before = self.manager.catalog_path.read_bytes()
        with patch.object(ag_versions, "github", side_effect=GuardError("offline")):
            with self.assertRaises(GuardError):
                self.manager.refresh(1)
        self.assertEqual(self.manager.catalog_path.read_bytes(), before)
        with patch.object(ag_versions, "github", return_value=([release()], '"new"')) as request:
            self.manager.refresh(1)
            request.assert_called_once_with("/releases?per_page=10&page=1", None)
        self.assertEqual(list(self.manager.status()["pages"]), ["1"])

    def test_switch_and_return_to_automatic_without_web_server_changes(self):
        self.make_cache(self.future)
        with patch.object(self.manager, "probe") as probe:
            self.manager.activate("override", "1.29.0")
            probe.assert_called_once_with("1.29.0")
        self.assertEqual(self.manager.state()["previous"], "1.28.1")
        self.assertEqual(self.manager.state()["mode"], "override")
        self.assertEqual(os.readlink(self.manager.cache / "active"), "1.29.0")
        self.assertEqual([c[0] for c in self.runtime.calls], ["stop", "prepare", "start"])
        self.runtime.calls.clear()
        with patch.object(self.manager, "probe"):
            self.manager.activate("automatic")
        self.assertEqual(self.manager.version(), "1.28.1")
        self.assertEqual(self.manager.state()["mode"], "automatic")
        self.assertFalse(any(call[0] in ("routing", "reconfigure") for call in self.runtime.calls))

    def test_same_version_only_changes_mode(self):
        with patch.object(self.manager, "probe", side_effect=AssertionError("unnecessary probe")):
            self.manager.activate("override", "1.28.1")
            self.manager.activate("automatic")
        self.assertEqual(self.runtime.calls, [])

    def test_override_survives_new_default_pin_and_bootstrap(self):
        self.make_cache(self.future)
        with patch.object(self.manager, "probe"):
            self.manager.activate("override", "1.29.0")
        new_pin = {**self.pin, "version": "1.30.0", "sha256": "d" * 64}
        self.make_cache(new_pin)
        (self.module / "runtime.lock.json").write_text(json.dumps(new_pin))
        self.manager.bootstrap()
        self.assertEqual(self.manager.version(), "1.29.0")
        self.assertEqual(self.manager.state()["mode"], "override")
        self.assertEqual(self.manager.status()["pinned_version"], "1.30.0")

    def test_automatic_follows_new_pin_only_when_explicitly_applied(self):
        self.make_cache(self.future)
        (self.module / "runtime.lock.json").write_text(json.dumps(self.future))
        self.manager.bootstrap()
        self.assertEqual(self.manager.version(), "1.28.1")
        with patch.object(self.manager, "probe"):
            self.manager.activate("automatic")
        self.assertEqual(self.manager.version(), "1.29.0")
        self.assertEqual(self.manager.state()["mode"], "automatic")
        self.assertEqual(self.runtime.status([])["runtime_version"], "1.29.0")

    def test_real_policies_and_environment_keep_database_namespaces_separate(self):
        config = self.runtime.read()["domains"]["7"]
        with patch.object(ag_runtime, "RUN", self.base / "run"):
            ag_runtime.Runtime.prepare(self.runtime, "7", config)
            old_store = self.base / "7/data/runtime-1.28.1/challenges.bdb"
            old_store.write_bytes(b"old runtime data")
            self.make_cache(self.future)
            with patch.object(self.manager, "probe"):
                self.manager.activate("override", "1.29.0")
            ag_runtime.Runtime.prepare(self.runtime, "7", config)
            generated = json.loads((self.base / "7/policies/1.29.0.json").read_text())
            self.assertIn("runtime-1.29.0/challenges.bdb", generated["store"]["parameters"]["path"])
            self.assertEqual(old_store.read_bytes(), b"old runtime data")
            environment = (self.base / "7/environment").read_text()
            self.assertIn('ANUBIS_RUNTIME_VERSION="1.29.0"', environment)
            self.assertIn('/policies/1.29.0.json', environment)
            self.assertTrue((self.base / "7/policies/1.28.1.json").exists())

    def test_failed_probe_does_not_touch_selection_or_services(self):
        self.make_cache(self.future)
        with patch.object(self.manager, "probe", side_effect=GuardError("incompatible policy")):
            with self.assertRaisesRegex(GuardError, "incompatible"):
                self.manager.activate("override", "1.29.0")
        self.assertEqual(self.runtime.calls, [])
        self.assertFalse(self.manager.pending.exists())
        self.assertEqual(self.manager.version(), "1.28.1")

    def test_multi_site_failure_rolls_back_and_suspended_sites_stay_stopped(self):
        self.make_cache(self.future)
        self.runtime.available.update({"8": {"id": 8, "name": "second.test", "hosting": "vrt_hst", "active": True},
                                       "9": {"id": 9, "name": "suspended.test", "hosting": "vrt_hst", "active": False}})
        state = self.runtime.read()
        state["domains"].update({k: dict(state["domains"]["7"]) for k in ("8", "9")})
        self.runtime.write(state)
        calls = []
        def start(ident):
            calls.append((ident, self.manager.version()))
            if ident == "8" and self.manager.version() == "1.29.0":
                raise GuardError("startup failed")
        self.runtime.start = start
        with patch.object(self.manager, "probe"):
            with self.assertRaisesRegex(GuardError, "restored"):
                self.manager.activate("override", "1.29.0")
        self.assertEqual(self.manager.version(), "1.28.1")
        self.assertEqual(calls, [("7", "1.29.0"), ("8", "1.29.0"), ("7", "1.28.1"), ("8", "1.28.1")])
        self.assertFalse(self.manager.pending.exists())

    def test_failed_rollback_retains_journal_and_blocks_conflicting_changes(self):
        self.make_cache(self.future)
        self.runtime.start = Mock(side_effect=GuardError("startup failed"))
        with patch.object(self.manager, "probe"):
            with self.assertRaisesRegex(GuardError, "journal retained"):
                self.manager.activate("override", "1.29.0")
        self.assertTrue(self.manager.pending.exists())
        with self.assertRaisesRegex(GuardError, "recovery"):
            self.runtime.apply("7", {"enabled": True})
        with self.assertRaisesRegex(GuardError, "recovery"):
            ag_versions.GeoIP(self.runtime).activate({"mode": "disabled"}, {}, None, [])
        self.runtime.start = Mock()
        with self.runtime.locked():
            self.manager.recover()
        self.assertFalse(self.manager.pending.exists())

    def test_interrupted_activation_restores_symlink_and_selection(self):
        previous = self.manager.state()
        self.make_cache(self.future)
        atomic(self.manager.pending, json.dumps({"previous": previous, "affected": ["7"]}))
        atomic(self.manager.state_path, json.dumps({**previous, "mode": "override", "version": "1.29.0"}))
        self.manager.link("1.29.0")
        with self.runtime.locked():
            self.manager.recover()
        self.assertEqual(self.manager.state(), previous)
        self.assertEqual(os.readlink(self.manager.cache / "active"), "1.28.1")

    def test_legacy_store_moves_only_after_stopping_and_remains_in_old_namespace(self):
        directory = self.base / "7/data"
        directory.mkdir(parents=True)
        (directory / "challenges.bdb").write_bytes(b"legacy challenge data")
        self.manager.migrate_legacy("7")
        self.assertEqual(self.runtime.calls[0], ("stop", "7"))
        self.assertEqual((directory / "runtime-1.28.1/challenges.bdb").read_bytes(), b"legacy challenge data")
        self.assertFalse((directory / "challenges.bdb").exists())
        self.make_cache(self.future)
        with patch.object(self.manager, "probe"):
            self.manager.activate("override", "1.29.0")
        self.assertEqual((directory / "runtime-1.28.1/challenges.bdb").read_bytes(), b"legacy challenge data")

    def test_invalid_requests_and_worker_queue_serialization(self):
        for payload in ({}, {"action": "exec"}, {"action": "refresh", "page": True}, {"action": "refresh", "page": 101},
                        {"action": "activate", "mode": "latest"}, {"action": "download", "version": "../x"},
                        {"action": "download", "version": "1.29.0", "url": "https://evil"}):
            with self.subTest(payload=payload), self.assertRaises(GuardError):
                self.manager.enqueue(payload)
        self.manager.enqueue({"action": "refresh", "page": 1})
        with self.assertRaisesRegex(GuardError, "queued"):
            self.manager.enqueue({"action": "refresh"})
        with patch.object(self.manager, "refresh") as refresh:
            self.assertTrue(self.manager.worker()["ok"])
            refresh.assert_called_once_with(1)
        self.assertEqual(self.manager.status()["job"]["status"], "succeeded")

    def test_launcher_executes_version_paired_with_domain_environment(self):
        script = self.manager.cache / "launch"
        # The global symlink changes independently; an old site's environment
        # must still execute its old binary until its own restart is prepared.
        self.make_cache(self.future)
        self.manager.link("1.29.0")
        with patch.dict(os.environ, {"ANUBIS_RUNTIME_VERSION": "1.28.1"}), patch('os.execv') as execute:
            runpy.run_path(str(script), run_name='__main__')
        self.assertEqual(execute.call_args.args[0], str(self.manager.cache / "1.28.1/bin/anubis"))
        with patch.dict(os.environ, {"ANUBIS_RUNTIME_VERSION": "../bad"}), self.assertRaises(SystemExit):
            runpy.run_path(str(script), run_name='__main__')

    def test_probe_executes_only_unprivileged_and_checks_http_as_well_as_health(self):
        run = self.base / "run"; run.mkdir()
        response = Mock(status=200)
        response.read.return_value = b"RIFFxxxxWEBP"
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(ag_runtime, "RUN", run), patch.object(ag_versions, "UnixConnection", return_value=connection), \
                patch.object(ag_versions, "execute", return_value="Anubis v1.28.1") as command:
            self.manager.probe("1.28.1")
        invocations = [call.args[0] for call in command.call_args_list]
        self.assertEqual(len(invocations), 3)
        self.assertIn("--property=User=plesk-anubis", invocations[0])
        self.assertIn("--property=User=plesk-anubis", invocations[1])
        self.assertEqual(invocations[0][-1], "--version")
        self.assertEqual(invocations[2][:2], ["/usr/bin/systemctl", "stop"])
        self.assertEqual(connection.request.call_args_list[0].args, ("GET", "/healthz"))
        self.assertIn("pensive.webp", connection.request.call_args_list[1].args[1])
        self.assertEqual(list(run.iterdir()), [])
        self.assertEqual(self.runtime.calls, [])

    def test_unhealthy_probe_stops_trial_unit_without_changing_production(self):
        run = self.base / "run"; run.mkdir()
        connection = Mock()
        connection.getresponse.return_value.status = 503
        with patch.object(ag_runtime, "RUN", run), patch.object(ag_versions, "UnixConnection", return_value=connection), \
                patch.object(ag_versions, "execute", return_value="Anubis v1.28.1") as command, \
                patch.object(ag_versions.time, "monotonic", side_effect=[0, 1, 9]), patch.object(ag_versions.time, "sleep"):
            with self.assertRaisesRegex(GuardError, "startup probe"):
                self.manager.probe("1.28.1")
        self.assertEqual(command.call_args.args[0][:2], ["/usr/bin/systemctl", "stop"])
        self.assertEqual(self.manager.version(), "1.28.1")
        self.assertEqual(self.runtime.calls, [])

    def test_installer_holds_apply_lock_from_probe_through_service_switch(self):
        run = self.base / "run"
        observed = []
        def locked(label):
            with (self.base / "apply.lock").open("a") as handle:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            observed.append(label)
        def write(path, *args, **kwargs):
            if not str(path).startswith("/etc/"):
                return atomic(path, *args, **kwargs)
        with patch.object(ag_runtime, "preflight"), patch.object(ag_runtime, "acquire"), \
                patch.object(ag_runtime, "install_artwork"), patch.object(ag_runtime, "RUN", run), \
                patch.object(ag_runtime, "Runtime", return_value=self.runtime), \
                patch.object(ag_runtime, "atomic", side_effect=write), patch.object(ag_runtime, "execute"), \
                patch.object(ag_runtime, "install_service_units", side_effect=lambda binary: locked("units")), \
                patch.object(ag_versions.Versions, "probe", side_effect=lambda version: locked("probe")) as probe, \
                patch.object(self.runtime, "reconcile"), patch.object(ag_runtime.pwd, "getpwnam"):
            self.assertTrue(ag_runtime.install()["ok"])
        self.assertEqual(observed, ["probe", "units"])
        probe.assert_called_once_with("1.28.1")
        self.assertIn(("start", "7"), self.runtime.calls)
        self.assertFalse(self.manager.pending.exists())
