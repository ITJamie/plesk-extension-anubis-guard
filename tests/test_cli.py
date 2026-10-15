"""Privileged command boundary tests; no root commands or sockets are opened."""
import io
from pathlib import Path
import runpy
import unittest
from unittest.mock import Mock, patch

ENTRY = Path(__file__).resolve().parents[1] / 'src/sbin/anubis-guard'
MAIN = runpy.run_path(str(ENTRY), run_name='anubis_guard_cli_test')['main']
GuardError = MAIN.__globals__['GuardError']


class CliScopeTests(unittest.TestCase):
    def invoke(self, args, payload):
        runtime = Mock()
        runtime.state_path = Path('/tmp/anubis-cli-test-unused/state.json')
        runtime.status.return_value = {'domains': []}
        with patch.dict(MAIN.__globals__, {'Runtime': lambda: runtime}), \
                patch('os.geteuid', return_value=0), patch('sys.stdin', payload):
            result = MAIN(args)
        return runtime, result

    def test_default_status_never_waits_for_stdin(self):
        stream = Mock()
        stream.read.side_effect = AssertionError('Interactive root status must not read stdin')
        runtime, _ = self.invoke(['status'], stream)
        runtime.status.assert_called_once_with()

    def test_scoped_status_passes_explicit_ids(self):
        runtime, _ = self.invoke(['status-scoped'], io.StringIO('{"ids":[7]}'))
        runtime.status.assert_called_once_with([7])

    def test_empty_scope_stays_empty(self):
        runtime, _ = self.invoke(['status-scoped'], io.StringIO('{"ids":[]}'))
        runtime.status.assert_called_once_with([])

    def test_missing_scope_cannot_fall_back_to_all_domains(self):
        for payload in ('', '{}', '{"ids":null}', '{"ids":[7],"all":true}'):
            with self.subTest(payload=payload), self.assertRaises(GuardError):
                self.invoke(['status-scoped'], io.StringIO(payload))

    def test_geoip_commands_are_fixed_and_payload_bounded(self):
        for command, method in (("geoip-status", "status"), ("geoip-worker", "worker"), ("geoip-refresh", "enqueue")):
            with self.subTest(command=command), patch('ag_geoip.GeoIP') as factory:
                self.invoke([command], Mock())
                getattr(factory.return_value, method).assert_called_once_with()
        with patch('ag_geoip.GeoIP') as factory:
            self.invoke(['geoip-save'], io.StringIO('{"mode":"disabled"}'))
            factory.return_value.enqueue.assert_called_once_with({'mode': 'disabled'})
        with self.assertRaises(GuardError):
            self.invoke(['geoip-save'], io.StringIO('x' * 65537))
        with self.assertRaises(GuardError):
            self.invoke(['geoip-status', '/arbitrary'], io.StringIO(''))

    def test_runtime_commands_are_fixed_and_payload_bounded(self):
        for command, method in (("runtime-status", "status"), ("runtime-worker", "worker")):
            with patch('ag_versions.Versions') as factory:
                self.invoke([command], Mock())
                getattr(factory.return_value, method).assert_called_once_with()
        with patch('ag_versions.Versions') as factory:
            self.invoke(['runtime-job'], io.StringIO('{"action":"rollback"}'))
            factory.return_value.enqueue.assert_called_once_with({'action': 'rollback'})
        with self.assertRaises(GuardError):
            self.invoke(['runtime-job'], io.StringIO('x' * 65537))
        with self.assertRaises(GuardError):
            self.invoke(['runtime-status', '/arbitrary'], io.StringIO(''))
