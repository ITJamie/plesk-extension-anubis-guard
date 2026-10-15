import json
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/sbin"))
from ag_core import GuardError, Transformer, apache_guard, domain_id, dump, ingress, parse, policy, settings, tokens

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "a" * 64


class ValidationTests(unittest.TestCase):
    def test_settings_are_normalized_and_deduplicated(self):
        self.assertEqual(settings({"enabled": True, "paths": ["/api", "/api"], "ips": ["192.0.2.1", "2001:db8::1/64"]}),
                         {"enabled": True, "paths": ["/api"], "ips": ["192.0.2.1/32", "2001:db8::/64"],
                          "challenge_mode": "adaptive", "difficulty": 2, "failure_mode": "closed",
                          "protection_scope": "all", "included_paths": [], "image_style": "original"})

    def test_image_style_is_a_fixed_choice(self):
        self.assertEqual(settings({"enabled": True})["image_style"], "original")
        self.assertEqual(settings({"enabled": True, "image_style": "generic"})["image_style"], "generic")
        for value in (None, True, {}, [], "../assets", "https://example.com", "generic;return 200"):
            with self.subTest(value=value), self.assertRaises(GuardError):
                settings({"enabled": True, "image_style": value})
            with self.subTest(transformer=value), self.assertRaises(GuardError):
                Transformer(7, SECRET, image_style=value)

    def test_selected_paths_normalize_and_deduplicate(self):
        result = settings({"enabled": True, "protection_scope": "selected",
                           "included_paths": ["/forums/*", "/forums/", "/forums", "/help/"]})
        self.assertEqual(result["included_paths"], ["/forums", "/help"])
        self.assertEqual(result["protection_scope"], "selected")

    def test_invalid_selected_paths_rejected(self):
        for value in ([], None, "/forums", ["/forums"] * 101, [True], ["/"], ["/*"], ["forums"],
                      ["//forums"], ["/forums//"], ["/forums/../admin"], ["/forums%2fadmin"],
                      ["/forums?x=1"], ["/forums#x"], ["/forums\\x"], ["/forums\n"],
                      ["/for*ums"], ["/forums/**"], ["/forums/*/private"], ['/forums"'], ["/$uri"],
                      ["/.within.website"], ["/.within.website/x"], ["/.well-known/acme-challenge/*"]):
            with self.subTest(value=value), self.assertRaises(GuardError):
                settings({"enabled": True, "protection_scope": "selected", "included_paths": value})
        for value in (True, {}, None, "SELECTED"):
            with self.subTest(scope=value), self.assertRaises(GuardError):
                settings({"enabled": True, "protection_scope": value})

    def test_failure_mode_is_strict_and_defaults_closed(self):
        self.assertEqual(settings({"enabled": True})["failure_mode"], "closed")
        self.assertEqual(settings({"enabled": True, "failure_mode": "open"})["failure_mode"], "open")
        for value in (None, True, [], {}, "OPEN", "http://evil", "open;return 200"):
            with self.subTest(value=value), self.assertRaises(GuardError):
                settings({"enabled": True, "failure_mode": value})
            with self.subTest(transformer=value), self.assertRaises(GuardError):
                Transformer(7, SECRET, failure_mode=value)

    def test_invalid_challenge_options(self):
        for key, values in (("challenge_mode", (None, [], {}, "slow", "ALLOW")),
                            ("difficulty", (None, True, "2", 2.5, 0, 7, -1))):
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(GuardError):
                    settings({"enabled": True, key: value})

    def test_adaptive_difficulty_scales_and_caps(self):
        for base, expected in ((1, [1, 3, 5]), (2, [2, 4, 6]), (5, [5, 6, 6]), (6, [6, 6, 6])):
            result = policy({"enabled": True, "difficulty": base}, "/data/db", "/run/metrics")
            self.assertEqual([rule["challenge"]["difficulty"] for rule in result["thresholds"][2:]], expected)
            self.assertEqual(result["thresholds"][0]["action"], "ALLOW")
            self.assertEqual(result["thresholds"][1]["challenge"], {"algorithm": "metarefresh", "difficulty": 1})

    def test_fixed_challenges_preserve_exclusions_and_default_rules(self):
        for mode, algorithm, difficulty in (("proof-of-work", "fast", 3), ("metarefresh", "metarefresh", 1)):
            result = policy({"enabled": True, "challenge_mode": mode, "difficulty": 3,
                             "paths": ["/api/"], "ips": ["192.0.2.0/24"]}, "/data/db", "/run/metrics")
            self.assertEqual([r.get("action") for r in result["bots"][:2]], ["ALLOW", "ALLOW"])
            self.assertEqual(result["bots"][-1]["name"], "generic-browser")
            self.assertEqual(len(result["thresholds"]), 1)
            self.assertEqual(result["thresholds"][0]["expression"], "true")
            self.assertEqual(result["thresholds"][0]["challenge"], {"algorithm": algorithm, "difficulty": difficulty})

    def test_invalid_domain_ids(self):
        for value in (True, 0, -1, "01", "1;id", "1/../../", "1.0"):
            with self.subTest(value=value), self.assertRaises(GuardError):
                domain_id(value)

    def test_invalid_exclusions(self):
        for value in ("/", "relative", "//example.test", "/a/../b", "/a/./b", "/a%2fb", "/a?b", "/a#b", "/a\\b", "/a\n", "/.within.website", "/.within.website/x", "/.with", "/a//b"):
            with self.subTest(value=value), self.assertRaises(GuardError):
                settings({"enabled": True, "paths": [value]})

    def test_bad_shape_and_bounds(self):
        for value in ({"enabled": 1}, {"enabled": "true"}, {"enabled": True, "target": "http://evil"},
                      {"enabled": True, "ips": ["1.2.3.999"]}, {"enabled": True, "ips": "127.0.0.1"},
                      {"enabled": True, "paths": ["/x"] * 101}):
            with self.subTest(value=value), self.assertRaises(GuardError):
                settings(value)

    def test_policy_precedes_embedded_defaults_and_persists(self):
        result = policy({"enabled": True, "paths": ["/a.b/"], "ips": ["192.0.2.0/24"]}, "/data/db", "/run/metrics")
        self.assertEqual(result["bots"][0]["path_regex"], r"^/a\.b/")
        self.assertEqual(result["bots"][-1]["name"], "generic-browser")
        self.assertEqual(result["store"]["backend"], "bbolt")
        self.assertEqual(result["metrics"]["network"], "unix")
        self.assertFalse(result["metrics"]["debug"])
        self.assertEqual(result["thresholds"][2]["challenge"]["difficulty"], 2)
        json.dumps(result)


class LexerTests(unittest.TestCase):
    def test_quotes_comments_variables_and_regex(self):
        text = '''# comment
server { set $x "a;{#b}"; set $y ${host}; location ~ "^/a{2}$" { return 200 'ok'; } }
'''
        result = parse(text)
        self.assertEqual(result[0].children[0].words[-1], '"a;{#b}"')
        self.assertEqual(result[0].children[1].words[-1], '${host}')
        self.assertEqual(dump(parse(dump(result))), dump(result))

    def test_escaped_space(self):
        self.assertEqual(tokens(r"root /a\ b;"), ["root", r"/a\ b", ";"])

    def test_malformed_config_rejected(self):
        for text in ("server {", "server }", 'set $a "abc;', "server { ; }", "server { root /a }"):
            with self.subTest(text=text), self.assertRaises(GuardError):
                parse(text)


class RoutingTests(unittest.TestCase):
    def transform(self, name="apache.conf", **kwargs):
        return Transformer(7, SECRET, read_include=lambda p: "fastcgi_param HTTPS $https if_not_empty; fastcgi_param REQUEST_SCHEME $scheme; fastcgi_param SERVER_PORT $server_port;", **kwargs).transform((FIXTURES / name).read_text())

    def test_entire_public_site_is_proxied(self):
        servers = parse(self.transform())
        self.assertEqual(len(servers), 3)
        edge = dump(servers[0].children)
        self.assertNotIn("try_files", edge)
        self.assertNotIn("7080", edge)
        self.assertNotIn("root ", edge)
        self.assertIn("/7/anubis.sock", edge)
        self.assertIn("/.well-known/acme-challenge/", edge)
        self.assertIn("return 503", edge)
        self.assertNotIn("proxy_next_upstream", edge)

    def test_fail_open_uses_private_vhost_backup_for_transport_failures_only(self):
        for name in ("apache.conf", "fpm.conf"):
            source = (FIXTURES / name).read_text()
            source += source.replace("18080;", "18443 ssl;").replace("18081;", "18444 ssl;")
            nodes = parse(Transformer(7, SECRET, failure_mode="open", read_include=lambda p:
                "fastcgi_param HTTPS $https; fastcgi_param REQUEST_SCHEME $scheme;").transform(source))
            groups = [n for n in nodes if n.name == "upstream"]
            self.assertEqual(len(groups), 2)
            self.assertNotEqual(groups[0].words[1], groups[1].words[1])
            for offset, group in enumerate(groups):
                servers = [n for n in nodes if n.name == "server"][offset * 3:offset * 3 + 3]
                edge, backend, router = servers
                primary, backup = group.children
                self.assertIn("/7/anubis.sock", primary.words[1])
                self.assertEqual(backup.words[2], "backup")
                self.assertEqual(backup.words[1], backend.children[0].words[1])
                common = next(n for n in edge.children if n.words == ["location", "/"])
                text = dump(common.children)
                self.assertIn(f"proxy_pass http://{group.words[1]};", text)
                self.assertIn("proxy_next_upstream error timeout;", text)
                self.assertIn("proxy_next_upstream_tries 2;", text)
                self.assertIn("proxy_connect_timeout 2s;", text)
                self.assertIn("proxy_intercept_errors off;", text)
                self.assertNotIn("non_idempotent", text)
                self.assertNotIn("http_", next(n for n in common.children if n.name == "proxy_next_upstream").words)
                self.assertIn("X-Real-IP $remote_addr", text)
                self.assertIn('X-Plesk-Anubis-Origin ""', text)
                self.assertIn("set_real_ip_from unix:", dump(backend.children))
                self.assertIn("return 503", dump(edge.children))
                acme = next(n for n in edge.children if n.words == ["location", "^~", "/.well-known/acme-challenge/"])
                self.assertNotIn("proxy_next_upstream", dump(acme.children))
            if name == "apache.conf":
                self.assertIn(SECRET, dump(nodes))
            else:
                self.assertIn("fastcgi_param REQUEST_SCHEME https;", dump(nodes))

    def test_explicit_closed_matches_legacy_routing(self):
        source = (FIXTURES / "apache.conf").read_text()
        self.assertEqual(Transformer(7, SECRET).transform(source),
                         Transformer(7, SECRET, failure_mode="closed").transform(source))

    def test_generic_images_are_exact_static_routes_only(self):
        for mode in ("closed", "open"):
            for scope, paths in (("all", []), ("selected", ["/forums"])):
                nodes = parse(self.transform(image_style="generic", failure_mode=mode, scope=scope, included_paths=paths))
                edge = next(n for n in nodes if n.name == "server")
                images = [n for n in edge.children if n.name == "location" and n.words[-1].endswith(".webp")]
                self.assertEqual(len(images), 3)
                self.assertEqual({n.words[-1].split('/')[-1] for n in images}, {"happy.webp", "pensive.webp", "reject.webp"})
                for location in images:
                    self.assertEqual(location.words[1], "=")
                    body = dump(location.children)
                    self.assertIn("/var/lib/plesk-anubis/assets/generic-v1/", body)
                    self.assertIn("image/webp", body)
                    self.assertIn('Cache-Control "no-store" always', body)
                    self.assertIn("limit_except GET", body)
                    self.assertNotIn("proxy_pass", body)
                    self.assertNotIn("$", body)
                self.assertTrue(any(n.words == ["location", "^~", "/.well-known/acme-challenge/"] for n in edge.children))
        self.assertNotIn("alias ", self.transform())

    def test_selected_paths_leave_other_urls_independent_of_anubis(self):
        from ag_core import unquote
        for mode in ("closed", "open"):
            text = self.transform(scope="selected", included_paths=["/forums/*", "/help"], failure_mode=mode)
            nodes = parse(text)
            edge, backend, router = [n for n in nodes if n.name == "server"]
            locations = [n for n in edge.children if n.name == "location"]
            def target_for(uri):
                candidates = [n for n in locations if n.words[1] != "@anubis_unavailable"]
                exact = [n for n in candidates if n.words[1] == "=" and unquote(n.words[-1]) == uri]
                prefixes = [n for n in candidates if n.words[1] != "=" and uri.startswith(unquote(n.words[-1]))]
                location = exact[0] if exact else max(prefixes, key=lambda n: len(unquote(n.words[-1])))
                return next(n.words[1] for n in location.children if n.name == "proxy_pass")
            direct = "http://" + backend.children[0].words[1]
            for uri in ("/", "/about", "/forums-other", "/Forums/post", "/helpful"):
                self.assertEqual(target_for(uri), direct, uri)
            for uri in ("/forums", "/forums/", "/forums/thread/123", "/help", "/help/index",
                        "/.within.website", "/.within.website/x/cmd/anubis/api/pass-challenge"):
                self.assertNotEqual(target_for(uri), direct, uri)
                self.assertIn("anubis", target_for(uri))
            self.assertIn("/7/r-", target_for("/.well-known/acme-challenge/token"))
            self.assertIn(SECRET, dump(backend.children))
            bypass = next(n for n in locations if n.words == ["location", "/"])
            self.assertNotIn("proxy_next_upstream", dump(bypass.children))
            self.assertIn("proxy_intercept_errors off;", dump(bypass.children))

    def test_backend_is_private_and_guarded(self):
        servers = parse(self.transform())
        backend = dump(servers[1].children)
        self.assertIn("listen unix:/run/plesk-anubis/7/b-", backend)
        self.assertNotIn("listen 127.0.0.1", backend)
        self.assertEqual(backend.count("X-Plesk-Anubis-Origin"), 2)
        self.assertIn(SECRET, backend)
        self.assertIn("real_ip_header X-Real-IP", backend)

    def test_original_request_headers_are_overwritten(self):
        edge = dump(parse(self.transform())[0].children)
        self.assertIn("proxy_set_header X-Real-IP $remote_addr;", edge)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", edge)
        self.assertIn('proxy_set_header Forwarded "";', edge)
        self.assertIn('proxy_set_header X-Plesk-Anubis-Origin "";', edge)
        self.assertRegex(edge, r'X-Plesk-Anubis-Route "[a-f0-9]{12}"')

    def test_fpm_configuration_is_preserved_with_original_scheme(self):
        result = self.transform("fpm.conf")
        backend = dump(parse(result)[1].children)
        self.assertIn("fastcgi_pass unix:", backend)
        self.assertIn("fastcgi_param REQUEST_SCHEME http;", backend)
        self.assertIn("fastcgi_param SERVER_PORT 18081;", backend)
        self.assertIn('fastcgi_param HTTPS "" if_not_empty;', backend)
        self.assertNotIn("include /etc/nginx/fastcgi", backend)

    def test_secure_backend_keeps_apache_transport_and_fpm_https(self):
        text = (FIXTURES / "fpm.conf").read_text().replace("18081;", "18443 ssl;")
        text = text.replace("root /", 'ssl_certificate /tmp/cert; ssl_certificate_key /tmp/key; root /')
        output = Transformer(7, SECRET, read_include=lambda p: "fastcgi_param HTTPS $https; fastcgi_param REQUEST_SCHEME $scheme;").transform(text)
        public, backend, _ = parse(output)
        self.assertIn("ssl_certificate /tmp/cert;", dump(public.children))
        self.assertNotIn("ssl_certificate", dump(backend.children))
        self.assertIn("fastcgi_param HTTPS on;", dump(backend.children))
        self.assertIn("fastcgi_param REQUEST_SCHEME https;", dump(backend.children))

    def test_redirect_is_preserved(self):
        text = 'server { listen 127.0.0.1:80; server_name example.test; location / { return 301 https://$host$request_uri; } }'
        output = Transformer(7, SECRET).transform(text)
        self.assertEqual(len(parse(output)), 1)
        self.assertIn("return 301", output)
        self.assertNotIn("anubis.sock", output)

    def test_unknown_includes_are_rejected(self):
        text = (FIXTURES / "apache.conf").read_text().replace("root /", "include /tmp/custom.conf; root /")
        with self.assertRaisesRegex(GuardError, "compatibility review"):
            Transformer(7, SECRET).transform(text)

    def test_custom_real_ip_is_rejected(self):
        text = (FIXTURES / "apache.conf").read_text().replace("root /", "real_ip_header CF-Connecting-IP; root /")
        with self.assertRaises(GuardError):
            Transformer(7, SECRET).transform(text)

    def test_http_and_https_and_ip_variants_get_distinct_routes(self):
        http = (FIXTURES / "apache.conf").read_text()
        text = http + http.replace("18080;", "18443 ssl;") + http.replace("127.0.0.1:", "[::1]:")
        output = Transformer(7, SECRET).transform(text)
        routes = re.findall(r'X-Plesk-Anubis-Route "([a-f0-9]{12})"', output)
        self.assertEqual(len(set(routes)), 3)

    def test_apache_origin_guard(self):
        output = apache_guard(SECRET)
        self.assertIn("[F,END]", output)
        self.assertIn(SECRET, output)
        self.assertNotIn("Require all granted", output)
        self.assertIn("RequestHeader unset X-Plesk-Anubis-Origin", output)
        self.assertIn("REDIRECT_ANUBIS_GUARD_OK", output)
        with self.assertRaises(GuardError):
            apache_guard("bad\nRewriteRule ^ - [L]")

    def test_ingress_target_is_domain_local_and_route_validated(self):
        output = ingress(7)
        parse(output)
        self.assertIn('"^[0-9a-f]{12}$"', output)
        self.assertIn("/7/r-$http_x_plesk_anubis_route.sock", output)
        self.assertNotIn("$http_host/", output)
        self.assertIn("client_max_body_size 0;", output)

    def test_origin_key_is_not_sent_to_unrelated_upstreams(self):
        text = (FIXTURES / "apache.conf").read_text().replace("http://127.0.0.1:7080", "http://external.example:9000")
        output = Transformer(7, SECRET).transform(text)
        self.assertNotIn(SECRET, output)

    def test_plesk_supplied_custom_backend_port_is_supported(self):
        target = "https://192.0.2.1:7443"
        text = (FIXTURES / "apache.conf").read_text().replace("http://127.0.0.1:7080", target)
        output = Transformer(7, SECRET, origins=[target]).transform(text)
        self.assertEqual(output.count(SECRET), 2)

    def test_hop_by_hop_header_lists_are_not_trusted(self):
        output = self.transform() + ingress(7)
        self.assertNotIn("$http_connection", output)
        self.assertIn("proxy_set_header Connection $anubis_guard_connection", output)


if __name__ == "__main__":
    unittest.main()
