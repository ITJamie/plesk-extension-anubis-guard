"""Exercise the real nginx parser without touching the installed configuration."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/sbin"))
from ag_core import Transformer, ingress


@unittest.skipUnless(shutil.which("nginx"), "nginx executable is not available")
class NginxSyntaxTests(unittest.TestCase):
    def test_generated_apache_and_fpm_configurations_compile(self):
        self.compile("closed")

    def test_fail_open_apache_and_fpm_configurations_compile(self):
        self.compile("open")

    def test_selected_paths_compile_in_both_failure_modes(self):
        for mode in ("closed", "open"):
            with self.subTest(mode=mode):
                self.compile(mode, scope="selected", included_paths=["/forums/*", "/help/", "/a space"])

    def test_generic_images_compile_for_all_and_selected_paths(self):
        for mode in ("closed", "open"):
            for scope, paths in (("all", []), ("selected", ["/forums"])):
                with self.subTest(mode=mode, scope=scope):
                    self.compile(mode, image_style="generic", scope=scope, included_paths=paths)

    def compile(self, failure_mode, **scope):
        with tempfile.TemporaryDirectory(prefix="ag-nginx-") as temp:
            root = Path(temp)
            (root / "7").mkdir()
            source = "\n".join(p.read_text() for p in sorted((Path(__file__).parent / "fixtures").glob("*.conf")))
            transformed = Transformer(7, "a" * 64, run=temp, read_include=lambda p: Path(p).read_text(),
                                      failure_mode=failure_mode, **scope).transform(source)
            temporary_paths = " ".join(f"{kind}_temp_path {root}/{kind};" for kind in ("client_body", "proxy", "fastcgi", "scgi", "uwsgi"))
            config = f'''user root root;
error_log stderr;
pid {root}/nginx.pid;
events {{}}
http {{
    access_log off;
    {temporary_paths}
    map $http_upgrade $anubis_guard_connection {{ default upgrade; '' close; }}
    {ingress(7, temp)}
    {transformed}
}}
'''
            (root / "nginx.conf").write_text(config)
            result = subprocess.run([shutil.which("nginx"), "-t", "-e", "stderr", "-p", temp + "/", "-c", str(root / "nginx.conf")],
                                    capture_output=True, text=True)
            # This managed workspace forbids sockets even for nginx -t. Require
            # parser success and permit only that specific post-parse limitation.
            self.assertIn("syntax is ok", result.stderr, result.stderr)
            if result.returncode:
                self.assertIn("Operation not permitted", result.stderr, result.stderr)
                self.assertIn("setsockopt", result.stderr, result.stderr)


if __name__ == "__main__":
    unittest.main()
