import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/sbin"))
import ag_runtime
from ag_core import GuardError


class FakeRuntime(ag_runtime.Runtime):
    def __init__(self, directory):
        super().__init__()
        self.state_path = directory / "state.json"
        self.calls = []
        self.fail = None
        self.available = {"7": {"id": 7, "name": "example.test", "hosting": "vrt_hst", "active": True}}

    def domains(self):
        return self.available

    def prepare(self, ident, config):
        self.calls.append(("prepare", ident, copy.deepcopy(config)))

    def start(self, ident):
        self.calls.append(("start", ident))
        if self.fail == "start":
            self.fail = None
            raise GuardError("startup failed")

    def stop(self, ident):
        self.calls.append(("stop", ident))

    def routing(self, state):
        self.calls.append(("routing", copy.deepcopy(state)))

    def reconfigure(self, name):
        self.calls.append(("reconfigure", name, self.read()))
        if self.fail == "reconfigure":
            self.fail = None
            raise GuardError("nginx config failed")


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patcher = patch.object(ag_runtime, "ROOT", self.root)
        self.patcher.start()
        self.runtime = FakeRuntime(self.root)
        self.settings = {"enabled": True, "paths": ["/api/"], "ips": []}

    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()

    def test_enable_is_persisted_before_plesk_regeneration(self):
        self.runtime.apply("7", self.settings)
        config = self.runtime.read()["domains"]["7"]
        self.assertTrue(config["enabled"])
        self.assertEqual(len(config["origin_key"]), 64)
        self.assertFalse((self.root / "pending.json").exists())
        regenerated = [c for c in self.runtime.calls if c[0] == "reconfigure"][0]
        self.assertTrue(regenerated[2]["domains"]["7"]["enabled"])

    def test_challenge_settings_persist_and_survive_failed_changes(self):
        self.runtime.apply("7", {**self.settings, "challenge_mode": "proof-of-work", "difficulty": 3})
        with patch.object(ag_runtime, "healthy", return_value=True):
            status = self.runtime.status([7])["domains"][0]
        self.assertEqual((status["challenge_mode"], status["difficulty"]), ("proof-of-work", 3))
        self.runtime.fail = "start"
        with self.assertRaises(GuardError):
            self.runtime.apply("7", {**self.settings, "challenge_mode": "metarefresh", "difficulty": 1})
        config = self.runtime.read()["domains"]["7"]
        self.assertEqual((config["challenge_mode"], config["difficulty"]), ("proof-of-work", 3))
        self.assertEqual(self.runtime.calls[-2][0], "prepare")
        self.assertEqual(self.runtime.calls[-2][2]["difficulty"], 3)

    def test_failure_mode_persists_controls_rendering_and_rolls_back(self):
        source = (Path(__file__).parent / "fixtures/apache.conf").read_text()
        self.runtime.apply("7", self.settings)
        self.assertNotIn("backup;", self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))
        self.runtime.apply("7", {**self.settings, "failure_mode": "open"})
        self.assertIn("backup;", self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))
        with patch.object(ag_runtime, "healthy", return_value=False):
            status = self.runtime.status([7])["domains"][0]
        self.assertEqual(status["failure_mode"], "open")
        self.runtime.fail = "reconfigure"
        with self.assertRaises(GuardError):
            self.runtime.apply("7", {**self.settings, "failure_mode": "closed"})
        self.assertEqual(self.runtime.read()["domains"]["7"]["failure_mode"], "open")
        self.assertIn("backup;", self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))
        self.runtime.apply("7", {**self.settings, "failure_mode": "closed"})
        self.assertNotIn("backup;", self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))

    def test_legacy_state_reports_and_renders_fail_closed(self):
        self.runtime.write({"version": 1, "domains": {"7": {**self.settings, "origin_key": "a" * 64}}})
        with patch.object(ag_runtime, "healthy", return_value=False):
            self.assertEqual(self.runtime.status([7])["domains"][0]["failure_mode"], "closed")
        source = (Path(__file__).parent / "fixtures/apache.conf").read_text()
        self.assertNotIn("backup;", self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))

    def test_selected_paths_persist_render_and_roll_back(self):
        source = (Path(__file__).parent / "fixtures/apache.conf").read_text()
        self.runtime.apply("7", {**self.settings, "protection_scope": "selected", "included_paths": ["/forums/*"]})
        with patch.object(ag_runtime, "healthy", return_value=True):
            status = self.runtime.status([7])["domains"][0]
        self.assertEqual((status["protection_scope"], status["included_paths"]), ("selected", ["/forums"]))
        self.assertIn('location = "/forums"', self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))
        self.runtime.fail = "reconfigure"
        with self.assertRaises(GuardError):
            self.runtime.apply("7", {**self.settings, "protection_scope": "selected", "included_paths": ["/private"]})
        self.assertEqual(self.runtime.read()["domains"]["7"]["included_paths"], ["/forums"])
        self.assertIn('location = "/forums"', self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))
        self.runtime.apply("7", {**self.settings, "protection_scope": "all", "included_paths": ["/forums"]})
        self.assertNotIn('location = "/forums"', self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))

    def test_image_choice_persists_and_rolls_back_with_routing(self):
        source = (Path(__file__).parent / "fixtures/apache.conf").read_text()
        self.runtime.apply("7", {**self.settings, "image_style": "generic"})
        with patch.object(ag_runtime, "healthy", return_value=True):
            self.assertEqual(self.runtime.status([7])["domains"][0]["image_style"], "generic")
        self.assertIn("alias ", self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))
        self.runtime.fail = "reconfigure"
        with self.assertRaises(GuardError):
            self.runtime.apply("7", {**self.settings, "image_style": "original"})
        self.assertEqual(self.runtime.read()["domains"]["7"]["image_style"], "generic")
        self.assertIn("alias ", self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))
        self.runtime.apply("7", {**self.settings, "image_style": "original"})
        self.assertNotIn("alias ", self.runtime.render("7", ag_runtime.Transformer.TEMPLATE, source))

    def test_disable_stops_service_after_routing_restored(self):
        self.runtime.apply("7", self.settings)
        self.runtime.calls.clear()
        self.runtime.apply("7", {**self.settings, "enabled": False})
        names = [c[0] for c in self.runtime.calls]
        self.assertLess(names.index("reconfigure"), names.index("stop"))

    def test_reconfiguration_failure_restores_enabled_policy_and_key(self):
        self.runtime.apply("7", self.settings)
        before = self.runtime.read()
        self.runtime.fail = "reconfigure"
        with self.assertRaisesRegex(GuardError, "nginx config failed"):
            self.runtime.apply("7", {**self.settings, "paths": ["/changed/"]})
        config = self.runtime.read()["domains"]["7"]
        self.assertTrue(config["enabled"])
        self.assertEqual(config["paths"], before["domains"]["7"]["paths"])
        self.assertEqual(config["origin_key"], before["domains"]["7"]["origin_key"])
        self.assertIn("nginx config failed", config["last_error"])
        self.assertFalse((self.root / "pending.json").exists())

    def test_first_enable_startup_failure_never_leaves_enabled_state(self):
        self.runtime.fail = "start"
        with self.assertRaisesRegex(GuardError, "startup failed"):
            self.runtime.apply("7", self.settings)
        self.assertFalse(self.runtime.read()["domains"]["7"]["enabled"])
        self.assertFalse(any(c[0] in ("routing", "reconfigure") for c in self.runtime.calls))
        self.assertIn(("stop", "7"), self.runtime.calls)

    def test_failed_policy_startup_restores_previous_service_without_web_regeneration(self):
        self.runtime.apply("7", self.settings)
        self.runtime.calls.clear()
        self.runtime.fail = "start"
        with self.assertRaisesRegex(GuardError, "startup failed"):
            self.runtime.apply("7", {**self.settings, "paths": ["/changed/"]})
        self.assertEqual(self.runtime.read()["domains"]["7"]["paths"], ["/api/"])
        self.assertFalse(any(c[0] in ("routing", "reconfigure") for c in self.runtime.calls))
        self.assertEqual(len([c for c in self.runtime.calls if c[0] == "start"]), 2)

    def test_origin_key_survives_disable_and_reenable(self):
        self.runtime.apply("7", self.settings)
        key = self.runtime.read()["domains"]["7"]["origin_key"]
        self.runtime.apply("7", {**self.settings, "enabled": False})
        self.runtime.apply("7", self.settings)
        self.assertEqual(self.runtime.read()["domains"]["7"]["origin_key"], key)

    def test_ineligible_domain_and_unknown_domain_rejected(self):
        with self.assertRaisesRegex(GuardError, "no longer exists"):
            self.runtime.apply("99", self.settings)
        self.runtime.available["7"]["active"] = False
        with self.assertRaisesRegex(GuardError, "active domains"):
            self.runtime.apply("7", self.settings)

    def test_disabled_hook_is_passthrough(self):
        self.assertEqual(self.runtime.render("7", "domain/nginxDomainVirtualHost.php", "original"), "original")

    def test_crash_journal_recovers_previous_state(self):
        self.runtime.apply("7", self.settings)
        previous = self.runtime.read()
        ag_runtime.atomic(self.root / "pending.json", json.dumps({"id": "7", "previous": previous, "domain": self.runtime.available["7"]}))
        self.runtime.write({"version": 1, "domains": {}})
        with patch.object(ag_runtime, "healthy", return_value=True):
            self.runtime.reconcile()
        self.assertEqual(self.runtime.read(), previous)
        self.assertFalse((self.root / "pending.json").exists())

    def test_atomic_files_are_private_and_replace_cleanly(self):
        target = self.root / "test.json"
        ag_runtime.atomic(target, "first")
        ag_runtime.atomic(target, "second")
        self.assertEqual(target.read_text(), "second")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.glob("*.new")), [])

    def test_crash_before_routing_does_not_regenerate_web_configuration(self):
        previous = {"version": 1, "domains": {}}
        ag_runtime.atomic(self.root / "pending.json", json.dumps({"id": "7", "previous": previous,
            "domain": self.runtime.available["7"], "routing_changed": False}))
        self.runtime.reconcile()
        self.assertFalse(any(c[0] in ("routing", "reconfigure") for c in self.runtime.calls))
        self.assertIn(("stop", "7"), self.runtime.calls)
        self.assertFalse((self.root / "pending.json").exists())

    def test_failed_rollback_keeps_recovery_journal(self):
        self.runtime.restore = lambda *a: (_ for _ in ()).throw(GuardError("rollback failed"))
        self.runtime.fail = "reconfigure"
        with self.assertRaisesRegex(GuardError, "rollback failed"):
            self.runtime.apply("7", self.settings)
        self.assertTrue((self.root / "pending.json").exists())

    def test_new_apply_cannot_overwrite_pending_recovery(self):
        pending = self.root / "pending.json"
        pending.write_text('{"original":"journal"}')
        with self.assertRaisesRegex(GuardError, "interrupted"):
            self.runtime.apply("7", self.settings)
        self.assertEqual(pending.read_text(), '{"original":"journal"}')

    def test_scoped_status_never_probes_or_returns_another_domain(self):
        self.runtime.available['8'] = {'id': 8, 'name': 'other-tenant.test', 'hosting': 'vrt_hst', 'active': True}
        self.runtime.write({'version': 1, 'domains': {
            '7': {**self.settings, 'last_error': '', 'origin_key': 'own-secret'},
            '8': {**self.settings, 'paths': ['/private/'], 'last_error': 'private error', 'origin_key': 'other-secret'},
        }})
        with patch.object(ag_runtime, 'healthy', return_value=True) as probe:
            result = self.runtime.status([7])
        self.assertEqual([d['id'] for d in result['domains']], [7])
        probe.assert_called_once_with('7')
        self.assertNotIn('private', json.dumps(result))
        self.assertNotIn('secret', json.dumps(result))

    def test_empty_status_scope_returns_no_domains_and_no_probes(self):
        with patch.object(ag_runtime, 'healthy') as probe:
            self.assertEqual(self.runtime.status([])['domains'], [])
        probe.assert_not_called()

    def test_unscoped_status_retains_root_cli_visibility(self):
        self.runtime.available['8'] = {'id': 8, 'name': 'other-tenant.test', 'hosting': 'vrt_hst', 'active': True}
        self.assertEqual([d['id'] for d in self.runtime.status()['domains']], [7, 8])

    def test_invalid_status_scopes_are_rejected(self):
        for ids in ('7', [True], ['7;id'], [7] * 10001):
            with self.subTest(ids_type=type(ids).__name__), self.assertRaises(GuardError):
                self.runtime.status(ids)


class ReconfigureTests(unittest.TestCase):
    def test_graceful_reload_preserves_panel_connection_and_apache_guard_order(self):
        with patch.object(ag_runtime.Path, "is_file", return_value=True), \
                patch.object(ag_runtime, "execute", side_effect=lambda args, **kw:
                    "active\n" if "show" in args else "") as command:
            ag_runtime.Runtime().reconfigure("example.test")
        calls = [c.args[0] for c in command.call_args_list]
        self.assertEqual(calls, [
            ["/usr/local/psa/admin/sbin/httpdmng", "--reconfigure-domain", "example.test", "-no-restart"],
            ["/usr/sbin/nginx", "-t"],
            ["/usr/bin/systemctl", "show", "httpd", "--property=ActiveState", "--value"],
            ["/usr/sbin/httpd", "-t"],
            ["/usr/bin/systemctl", "reload", "httpd"],
            ["/usr/bin/systemctl", "reload", "nginx"],
        ])

    def test_nginx_only_and_inactive_apache_do_not_start_apache(self):
        for installed, active in ((False, ""), (True, "inactive\n")):
            with self.subTest(installed=installed), patch.object(ag_runtime.Path, "is_file", return_value=installed), \
                    patch.object(ag_runtime, "execute", return_value=active) as command:
                ag_runtime.Runtime().reconfigure("example.test")
            calls = [c.args[0] for c in command.call_args_list]
            self.assertEqual(calls[-1], ["/usr/bin/systemctl", "reload", "nginx"])
            self.assertNotIn(["/usr/bin/systemctl", "reload", "httpd"], calls)
            self.assertFalse(any("restart" in args or "start" in args for args in calls))

    def test_invalid_config_never_reloads_services(self):
        for failed in ("/usr/sbin/nginx", "/usr/sbin/httpd"):
            def execute(args, **kwargs):
                if args[0] == failed:
                    raise GuardError("invalid config")
                return "active\n" if "show" in args else ""
            with self.subTest(failed=failed), patch.object(ag_runtime.Path, "is_file", return_value=True), \
                    patch.object(ag_runtime, "execute", side_effect=execute) as command:
                with self.assertRaisesRegex(GuardError, "invalid config"):
                    ag_runtime.Runtime().reconfigure("example.test")
            self.assertFalse(any("reload" in c.args[0] for c in command.call_args_list))


class DirectoryPermissionTests(unittest.TestCase):
    def test_artwork_is_published_with_nginx_read_access_and_repaired(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(ag_runtime, "ROOT", Path(temp)), \
                patch.object(ag_runtime.os, "chown") as ownership:
            ag_runtime.install_artwork()
            target = Path(temp) / "assets/generic-v1"
            self.assertEqual(target.stat().st_mode & 0o777, 0o750)
            for name in ("happy", "pensive", "reject"):
                path = target / (name + ".webp")
                expected = (Path(ag_runtime.__file__).parent / "assets/generic-v1" / path.name).read_bytes()
                self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            path.write_bytes(b"damaged")
            ag_runtime.os.chmod(path, 0o600)
            ag_runtime.install_artwork()
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            ownership.assert_any_call(path, 0, ag_runtime.grp.getgrnam("nginx").gr_gid)

    def test_prepare_repairs_permissions_under_restrictive_umasks(self):
        for mask in (0o027, 0o077):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "state"
                root.mkdir()
                run = Path(temp) / "run"
                account = SimpleNamespace(pw_uid=123)
                groups = {ag_runtime.USER: SimpleNamespace(gr_gid=456), "nginx": SimpleNamespace(gr_gid=789)}
                old_mask = ag_runtime.os.umask(mask)
                try:
                    with patch.object(ag_runtime, "ROOT", root), patch.object(ag_runtime, "RUN", run), \
                            patch.object(ag_runtime.pwd, "getpwnam", return_value=account), \
                            patch.object(ag_runtime.grp, "getgrnam", side_effect=lambda name: groups[name]), \
                            patch.object(ag_runtime.os, "chown") as ownership:
                        runtime = ag_runtime.Runtime()
                        config = {"enabled": True, "paths": [], "ips": []}
                        runtime.prepare("7", config)
                        self.assertEqual((run / "7").stat().st_mode & 0o777, 0o770)
                        self.assertEqual(run.stat().st_mode & 0o777, 0o755)
                        self.assertEqual((root / "7").stat().st_mode & 0o777, 0o750)
                        self.assertEqual((root / "7/data").stat().st_mode & 0o777, 0o700)
                        ownership.assert_any_call(run / "7", 0, 789)
                        # Existing directories created by a prior version are repaired too.
                        ag_runtime.os.chmod(run / "7", 0o750)
                        key_before = (root / "7/signing-key").read_bytes()
                        runtime.prepare("7", config)
                        self.assertEqual((run / "7").stat().st_mode & 0o777, 0o770)
                        self.assertEqual((root / "7/signing-key").read_bytes(), key_before)
                        runtime.prepare("7", {**config, "challenge_mode": "proof-of-work", "difficulty": 3})
                        rendered = json.loads((root / "7/policy.json").read_text())
                        self.assertEqual(rendered["thresholds"][0]["challenge"], {"algorithm": "fast", "difficulty": 3})
                finally:
                    ag_runtime.os.umask(old_mask)


class StartupTests(unittest.TestCase):
    def test_successful_start_returns_after_health_check(self):
        with patch.object(ag_runtime, "execute", return_value="") as command, \
                patch.object(ag_runtime, "healthy", return_value=True):
            ag_runtime.Runtime().start("7")
        command.assert_called_once_with(["/usr/bin/systemctl", "restart", "plesk-anubis@7.service"], timeout=15)

    def test_crash_is_reported_without_waiting_for_repeated_restarts(self):
        for status in ("ActiveState=activating\nSubState=auto-restart\nExecMainStatus=1\n",
                       "ActiveState=failed\nSubState=failed\nExecMainStatus=1\n"):
            with self.subTest(status=status), patch.object(ag_runtime, "execute", side_effect=["", status]), \
                    patch.object(ag_runtime, "healthy", return_value=False), \
                    patch.object(ag_runtime.time, "sleep") as sleep:
                with self.assertRaisesRegex(GuardError, "journalctl -u plesk-anubis@7.service"):
                    ag_runtime.Runtime().start("7")
                sleep.assert_not_called()

    def test_health_wait_has_a_deadline_instead_of_thirty_socket_timeouts(self):
        with patch.object(ag_runtime, "execute", side_effect=["", "ActiveState=active\nSubState=running\n"]), \
                patch.object(ag_runtime, "healthy", return_value=False) as health, \
                patch.object(ag_runtime.time, "monotonic", side_effect=[0, 0, 0, 8, 8]), \
                patch.object(ag_runtime.time, "sleep"):
            with self.assertRaisesRegex(GuardError, "within 8 seconds"):
                ag_runtime.Runtime().start("7")
        self.assertLessEqual(health.call_args.kwargs["timeout"], 1)


if __name__ == "__main__":
    unittest.main()
