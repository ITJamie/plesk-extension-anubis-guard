"""Pure configuration logic. No Plesk imports or privileged side effects."""
from dataclasses import dataclass, field
import ipaddress
import json
import re
from pathlib import Path


class GuardError(Exception):
    pass


def domain_id(value):
    if isinstance(value, bool) or not re.fullmatch(r"[1-9][0-9]{0,9}", str(value)):
        raise GuardError("Invalid Plesk domain ID")
    return int(value)


def protection_scope(scope="all", paths=None):
    if not isinstance(scope, str) or scope not in ("all", "selected"):
        raise GuardError("Protection scope must be all or selected")
    if not isinstance(paths, list) or len(paths) > 100:
        raise GuardError("Provide at most 100 protected paths")
    clean = []
    for value in paths:
        if not isinstance(value, str) or not value or len(value) > 1024:
            raise GuardError("Invalid protected path")
        if value.endswith("/*"):
            value = value[:-1]
        if (not value.startswith("/") or "//" in value
                or any(ord(c) < 32 or ord(c) == 127 for c in value)
                or any(c in value for c in '?%#\\$"*')
                or any(p in (".", "..") for p in value.split("/"))):
            raise GuardError("Use an absolute protected path, optionally ending in /*, without query strings or traversal")
        value = value.rstrip("/")
        if not value:
            raise GuardError("Choose the entire-site scope to protect /")
        if value == "/.within.website" or value.startswith("/.within.website/"):
            raise GuardError("Anubis challenge paths cannot be selected as website content")
        if value == "/.well-known/acme-challenge" or value.startswith("/.well-known/acme-challenge/"):
            raise GuardError("ACME challenge paths must remain available without protection")
        if value not in clean:
            clean.append(value)
    if scope == "selected" and not clean:
        raise GuardError("Add at least one protected path for selected-path protection")
    return scope, clean


def settings(data):
    if not isinstance(data, dict) or set(data) - {"enabled", "paths", "ips", "challenge_mode", "difficulty", "failure_mode", "protection_scope", "included_paths", "image_style"}:
        raise GuardError("Unexpected website protection settings")
    if type(data.get("enabled")) is not bool:
        raise GuardError("Enabled must be a boolean")
    mode = data.get("challenge_mode", "adaptive")
    difficulty = data.get("difficulty", 2)
    if not isinstance(mode, str) or mode not in ("adaptive", "proof-of-work", "metarefresh"):
        raise GuardError("Choose adaptive, proof-of-work or metarefresh challenges")
    if type(difficulty) is not int or not 1 <= difficulty <= 6:
        raise GuardError("Proof-of-work difficulty must be an integer from 1 to 6")
    failure_mode = data.get("failure_mode", "closed")
    if not isinstance(failure_mode, str) or failure_mode not in ("closed", "open"):
        raise GuardError("Failure mode must be closed or open")
    result = {"enabled": data["enabled"], "challenge_mode": mode, "difficulty": difficulty,
              "failure_mode": failure_mode}
    image_style = data.get("image_style", "original")
    if not isinstance(image_style, str) or image_style not in ("original", "generic"):
        raise GuardError("Challenge images must be original or generic")
    result["image_style"] = image_style
    result["protection_scope"], result["included_paths"] = protection_scope(
        data.get("protection_scope", "all"), data.get("included_paths", []))
    for key in ("paths", "ips"):
        values = data.get(key, [])
        if not isinstance(values, list) or len(values) > 100:
            raise GuardError("At most 100 exclusions of each kind are supported")
        clean = []
        for value in values:
            if not isinstance(value, str) or not value or len(value) > 1024:
                raise GuardError("Invalid exclusion")
            if key == "paths":
                if (not value.startswith("/") or value.startswith("//")
                        or any(ord(c) < 32 or ord(c) == 127 for c in value)
                        or any(c in value for c in "?%#\\")
                        or any(p in (".", "..") for p in value.split("/"))
                        or "//" in value):
                    raise GuardError("Use an absolute, decoded path prefix without query strings or traversal")
                if value == "/" or value.startswith("/.within.website") or "/.within.website".startswith(value):
                    raise GuardError("The root and Anubis challenge paths cannot be excluded")
            else:
                try:
                    value = str(ipaddress.ip_network(value, strict=False))
                except ValueError as exc:
                    raise GuardError("Invalid IPv4/IPv6 address or CIDR") from exc
            if value not in clean:
                clean.append(value)
        result[key] = clean
    return result


def policy(config, storage, metrics, geoip=None):
    """Keep embedded bot rules; configure the fallback challenge thresholds."""
    config = settings(config)
    bots = []
    for index, prefix in enumerate(config["paths"]):
        # Go regexp syntax; escape literals rather than accepting user expressions.
        escaped = re.sub(r"([\\.^$|?*+()\[\]{}])", r"\\\1", prefix)
        bots.append({"name": f"plesk-path-{index}", "path_regex": "^" + escaped, "action": "ALLOW"})
    if config["ips"]:
        bots.append({"name": "plesk-ip-exclusions", "remote_addresses": config["ips"], "action": "ALLOW"})
    # Whole dependent rules must be omitted: removing just a condition could
    # accidentally turn a rule into an unconditional allow/deny/weight.
    defaults = json.loads((Path(__file__).parent / "data/default-rules.json").read_text())
    bots.extend(rule for rule in defaults if geoip or not ({"asns", "geoip"} & set(rule)))
    result = {
        "bots": bots, "dnsbl": False,
        "honeypot": {"enabled": True, "implementation": "naive"},
        "openGraph": {"enabled": False, "considerHost": True, "ttl": "24h"},
        "status_codes": {"CHALLENGE": 200, "DENY": 200},
        "store": {"backend": "bbolt", "parameters": {"path": storage}},
        "metrics": {"bind": metrics, "network": "unix", "socketMode": "0600", "debug": False},
        "thresholds": [
            {"name": "minimal-suspicion", "expression": "weight <= 0", "action": "ALLOW"},
            {"name": "mild-suspicion", "expression": {"all": ["weight > 0", "weight < 10"]},
             "action": "CHALLENGE", "challenge": {"algorithm": "metarefresh", "difficulty": 1}},
            *[{"name": name, "expression": expression, "action": "CHALLENGE",
               "challenge": {"algorithm": "fast", "difficulty": difficulty}}
              for name, expression, difficulty in (
                  ("moderate-suspicion", {"all": ["weight >= 10", "weight < 20"]}, config["difficulty"]),
                  ("mild-proof-of-work", {"all": ["weight >= 20", "weight < 30"]}, min(config["difficulty"] + 2, 6)),
                  ("extreme-suspicion", "weight >= 30", min(config["difficulty"] + 4, 6)))]
        ] if config["challenge_mode"] == "adaptive" else [{
            "name": "plesk-site-challenge", "expression": "true", "action": "CHALLENGE",
            "challenge": {"algorithm": "fast" if config["challenge_mode"] == "proof-of-work" else "metarefresh",
                          "difficulty": config["difficulty"] if config["challenge_mode"] == "proof-of-work" else 1},
        }],
    }
    if geoip:
        result["geoip"] = {kind: {"path": geoip[kind]} for kind in ("country", "asn")}
    return result


@dataclass
class Directive:
    words: list
    children: object = None

    @property
    def name(self):
        return self.words[0] if self.words else ""


def tokens(text):
    """Nginx lexer: comments, quoted/escaped strings and ${variables} are atomic."""
    result, word, quote, pos = [], "", None, 0
    while pos < len(text):
        char = text[pos]
        if char == "\\":
            if pos + 1 >= len(text):
                raise GuardError("Unterminated nginx escape")
            word += text[pos:pos + 2]
            pos += 2
            continue
        if quote:
            word += char
            if char == quote:
                quote = None
            pos += 1
            continue
        if char in "\"'":
            quote = char
            word += char
        elif char == "#":
            if word:
                result.append(word)
                word = ""
            end = text.find("\n", pos)
            pos = len(text) if end == -1 else end
            continue
        elif char == "{" and word.endswith("$"):
            end = text.find("}", pos)
            if end < 0:
                raise GuardError("Unterminated nginx variable")
            word += text[pos:end + 1]
            pos = end + 1
            continue
        elif char.isspace() or char in "{};":
            if word:
                result.append(word)
                word = ""
            if char in "{};":
                result.append(char)
        else:
            word += char
        pos += 1
    if quote:
        raise GuardError("Unterminated nginx string")
    if word:
        result.append(word)
    return result


def parse(text):
    stream = iter(tokens(text))

    def block(nested=False):
        output, words = [], []
        for token in stream:
            if token == "}":
                if words or not nested:
                    raise GuardError("Unexpected nginx block ending")
                return output
            if token in (";", "{"):
                if not words:
                    raise GuardError("Empty nginx directive")
                output.append(Directive(words, block(True) if token == "{" else None))
                words = []
            else:
                words.append(token)
        if words or nested:
            raise GuardError("Incomplete nginx configuration")
        return output

    return block()


def dump(nodes, depth=0):
    result = []
    for node in nodes:
        line = "    " * depth + " ".join(node.words)
        result.append(line + (";\n" if node.children is None else " {\n" + dump(node.children, depth + 1) + "    " * depth + "}\n"))
    return "".join(result)


def unquote(word):
    return word[1:-1] if len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'" else word


def quoted(value):
    if any(c in value for c in '\n\r\x00$"\\'):
        raise GuardError("Unsafe generated nginx literal")
    return '"' + value + '"'


def is_redirect(nodes):
    locations = [n for n in nodes if n.name == "location"]
    return (len(locations) == 1 and locations[0].words == ["location", "/"]
            and len(locations[0].children) == 1 and locations[0].children[0].name == "return")


class Transformer:
    """Split rendered Plesk vhosts into TLS edges and unchanged private routing.

    One Anubis process feeds a private scheme router. A separate backend socket
    per original server preserves dual-stack/default-vhost and HTTP/HTTPS choices.
    """
    EDGE = {"listen", "server_name", "http2", "http3", "client_max_body_size",
            "client_body_timeout", "send_timeout", "access_log", "error_log",
            "ssl_certificate", "ssl_certificate_key", "ssl_protocols", "ssl_ciphers",
            "ssl_prefer_server_ciphers", "ssl_session_cache", "ssl_session_timeout",
            "ssl_session_tickets", "ssl_dhparam", "ssl_stapling", "ssl_stapling_verify",
            "ssl_trusted_certificate", "ssl_ecdh_curve", "ssl_buffer_size", "resolver",
            "resolver_timeout", "ssl_conf_command", "ssl_early_data"}
    TEMPLATE = "domain/nginxDomainVirtualHost.php"

    def __init__(self, ident, secret, run="/run/plesk-anubis", read_include=None, origins=None, failure_mode="closed",
                 scope="all", included_paths=None, image_style="original",
                 artwork_root="/var/lib/plesk-anubis/assets/generic-v1"):
        self.ident = domain_id(ident)
        if not re.fullmatch(r"[0-9a-f]{64}", secret):
            raise GuardError("Missing origin key")
        self.secret = secret
        if not isinstance(failure_mode, str) or failure_mode not in ("closed", "open"):
            raise GuardError("Failure mode must be closed or open")
        self.failure_mode = failure_mode
        self.scope, self.included_paths = protection_scope(scope, [] if included_paths is None else included_paths)
        if not isinstance(image_style, str) or image_style not in ("original", "generic"):
            raise GuardError("Challenge images must be original or generic")
        self.image_style = image_style
        self.artwork_root = artwork_root
        self.base = f"{run}/{self.ident}"
        self.read_include = read_include
        self.origins = set(origins if origins is not None else (
            "http://127.0.0.1:7080", "https://127.0.0.1:7081"))
        from urllib.parse import urlsplit
        for origin in self.origins:
            parsed = urlsplit(origin)
            if parsed.scheme not in ("http", "https") or parsed.path or parsed.query or parsed.fragment or parsed.username:
                raise GuardError("Invalid Plesk Apache origin")
            try:
                ipaddress.ip_address(parsed.hostname)
                if not parsed.port:
                    raise ValueError("Missing origin port")
            except ValueError as exc:
                raise GuardError("Invalid Plesk Apache origin") from exc

    def proxy(self, target, scheme, port, tls, original_protocol="$server_protocol", failover=False, bypass=False):
        # Retry transport failures only. Do not retry HTTP error/denial responses,
        # invalid headers, or opt into replaying non-idempotent requests.
        failure_directives = '''proxy_next_upstream error timeout;
            proxy_next_upstream_tries 2;
            proxy_connect_timeout 2s;
            proxy_intercept_errors off;''' if failover else ('proxy_intercept_errors off;' if bypass else 'proxy_intercept_errors on;')
        destination = target if failover else f"unix:{target}"
        return parse(f'''
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Proto {scheme};
            proxy_set_header X-Forwarded-Port {port};
            proxy_set_header Forwarded "";
            proxy_set_header X-Http-Version {original_protocol};
            proxy_set_header X-TLS-SNI-Name $ssl_server_name;
            proxy_set_header X-Plesk-Anubis-Https {tls};
            proxy_set_header X-Plesk-Anubis-Port {port};
            proxy_set_header X-Plesk-Anubis-Origin "";
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $anubis_guard_connection;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_read_timeout 3600s;
            {failure_directives}
            error_page 502 504 =503 @anubis_unavailable;
            proxy_pass http://{destination};
        ''')

    def backend(self, nodes, secure, port):
        result = []
        for node in nodes:
            if node.name in {"listen", "http2", "http3"} or node.name.startswith("ssl_"):
                continue
            if node.name in {"set_real_ip_from", "real_ip_header", "real_ip_recursive"}:
                raise GuardError("Custom real-IP directives require manual compatibility review")
            if node.name == "include":
                path = unquote(node.words[1])
                if path in ("/etc/nginx/fastcgi.conf", "/etc/nginx/fastcgi_params") and self.read_include:
                    result.extend(self.backend(parse(self.read_include(path)), secure, port))
                    continue
                # A customer include may open an alternate route or overwrite headers.
                # Reject rather than partially filtering an unknown configuration.
                raise GuardError(f"Included configuration requires compatibility review: {path}")
            if node.name == "add_header" and len(node.words) > 1 and unquote(node.words[1]).lower() == "alt-svc":
                continue
            def replace(word):
                if word == "$https" and not secure:
                    return '""'
                return re.sub(r"\$(scheme|https|server_port)\b", lambda m: {
                    "scheme": "https" if secure else "http", "https": "on" if secure else "",
                    "server_port": str(port)}[m[1]], word)
            words = [replace(w) for w in node.words]
            children = self.backend(node.children, secure, port) if node.children is not None else None
            # proxy_set_header inheritance stops when a child defines any headers.
            # Put the origin key beside each proxy_pass, not just at server level.
            result.append(Directive(words, children))
            if node.name == "proxy_pass" and unquote(node.words[1]) in self.origins:
                result.extend(parse(f'proxy_set_header X-Plesk-Anubis-Origin "{self.secret}";'))
        return result

    def transform(self, text):
        roots = parse(text)
        output = []
        for node in roots:
            if node.name != "server":
                raise GuardError("Unexpected directive in domain vhost template")
            children = node.children
            if is_redirect(children):
                output.append(node)
                continue
            listens = [n for n in children if n.name == "listen"]
            if not listens:
                raise GuardError("Domain vhost has no listen directive")
            secure = any("ssl" in n.words for n in listens)
            if any("unix:" in " ".join(n.words) for n in listens):
                raise GuardError("Anubis template was already transformed")
            # The template can emit an SEO redirect followed by the content server.
            # Listen addresses and server names are hashed to avoid duplicate sockets.
            import hashlib
            names = [n.words for n in children if n.name == "server_name"]
            identity = json.dumps([names, [n.words for n in listens]], sort_keys=True)
            suffix = hashlib.sha256(identity.encode()).hexdigest()[:12]
            sock = f"{self.base}/b-{suffix}.sock"
            route = f"{self.base}/r-{suffix}.sock"
            failover = self.failure_mode == "open"
            upstream = f"anubis_guard_{self.ident}_{suffix}"
            if failover:
                # Each original vhost has its own private backup, preserving
                # the IP, TLS and backend routing selected by Plesk.
                output += parse(f'''upstream {upstream} {{
                    server unix:{self.base}/anubis.sock max_fails=1 fail_timeout=2s;
                    server unix:{sock} backup;
                }}''')
            port_match = re.search(r":([0-9]+)$", unquote(listens[0].words[1]))
            if not port_match:
                raise GuardError("Unsupported nginx listen address")
            port = int(port_match[1])
            backend = self.backend(children, secure, port)
            backend = parse(f'''listen unix:{sock};
                set_real_ip_from unix:;
                real_ip_header X-Real-IP;
                port_in_redirect off;
                absolute_redirect off;''') + backend
            # Use the route identifier to preserve the original vhost/IP/scheme.
            # It is set at the edge and validated in the private router.
            edge = [n for n in children if n.name in self.EDGE or (
                n.name == "add_header" and len(n.words) > 1 and unquote(n.words[1]).lower() == "alt-svc")]
            # These directives are inherited by all public locations.
            edge += parse('''location @anubis_unavailable {
                default_type text/plain;
                return 503 "Website protection is temporarily unavailable. Please try again shortly.\\n";
            }''')
            if self.image_style == "generic":
                # Exact filenames only: no directory alias or variable-based
                # filesystem lookup, and no interception of challenge JS/APIs.
                for name in ("happy", "pensive", "reject"):
                    edge += parse(f'''location = /.within.website/x/cmd/anubis/static/img/{name}.webp {{
                        alias {quoted(self.artwork_root + '/' + name + '.webp')};
                        types {{ image/webp webp; }}
                        default_type image/webp;
                        add_header Cache-Control "no-store" always;
                        add_header X-Content-Type-Options nosniff always;
                        limit_except GET {{ deny all; }}
                    }}''')
            common = self.proxy(upstream if failover else f"{self.base}/anubis.sock",
                                "$scheme", "$server_port", 'on' if secure else '""', failover=failover)
            common += parse(f'proxy_set_header X-Plesk-Anubis-Route "{suffix}";')
            if self.scope == "all":
                edge.append(Directive(["location", "/"], common))
            else:
                # Match section boundaries, not /forums-other. nginx uses its
                # normalized URI, so query strings/encoded URLs cannot select an
                # alternate edge route. Original content processing stays private.
                bypass = self.proxy(sock, "$scheme", "$server_port", 'on' if secure else '""', bypass=True)
                bypass += parse(f'proxy_set_header X-Plesk-Anubis-Route "{suffix}";')
                edge.append(Directive(["location", "/"], bypass))
                for prefix in self.included_paths + ["/.within.website"]:
                    edge.append(Directive(["location", "=", quoted(prefix)], common))
                    edge.append(Directive(["location", "^~", quoted(prefix + "/")], common))
            acme = self.proxy(route, "$scheme", "$server_port", 'on' if secure else '""')
            acme = parse('if ($uri !~ "^/[.]well-known/acme-challenge/[A-Za-z0-9_-]+$") { return 404; }') + acme
            acme += parse(f'proxy_set_header X-Plesk-Anubis-Route "{suffix}";')
            edge.append(Directive(["location", "^~", "/.well-known/acme-challenge/"], acme))
            # Route socket is private, including ACME: never a public content listener.
            router = parse(f'''listen unix:{route};
                server_name _;
                client_max_body_size 0;
                location / {{
                    proxy_http_version 1.1;
                    proxy_set_header Host $http_host;
                    proxy_set_header X-Real-IP $http_x_real_ip;
                    proxy_set_header X-Forwarded-For $http_x_real_ip;
                    proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
                    proxy_set_header Upgrade $http_upgrade;
                    proxy_set_header Connection $anubis_guard_connection;
                    proxy_buffering off;
                    proxy_request_buffering off;
                    proxy_read_timeout 3600s;
                    proxy_pass http://unix:{sock};
                }}''')
            output += [Directive(["server"], edge), Directive(["server"], backend), Directive(["server"], router)]
        return "# Managed by Anubis Guard; regenerated by Plesk\n" + dump(output)


def ingress(ident, run="/run/plesk-anubis"):
    """Only route to generated sockets with a fixed domain-local identifier."""
    ident = domain_id(ident)
    return f'''server {{
        listen unix:{run}/{ident}/router.sock;
        server_name _;
        client_max_body_size 0;
        location / {{
            if ($http_x_plesk_anubis_route !~ "^[0-9a-f]{{12}}$") {{ return 400; }}
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $http_x_real_ip;
            proxy_set_header X-Forwarded-For $http_x_real_ip;
            proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $anubis_guard_connection;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_read_timeout 3600s;
            proxy_pass http://unix:{run}/{ident}/r-$http_x_plesk_anubis_route.sock;
        }}
    }}
'''


def apache_guard(secret):
    if not re.fullmatch(r"[0-9a-f]{64}", secret):
        raise GuardError("Missing origin key")
    return f'''# Anubis Guard: block direct requests to Apache backend ports.
RewriteEngine On
RewriteCond %{{HTTP:X-Plesk-Anubis-Origin}} ^{secret}$ [OR]
RewriteCond %{{ENV:REDIRECT_ANUBIS_GUARD_OK}} =1 [OR]
RewriteCond %{{ENV:ANUBIS_GUARD_OK}} =1
RewriteRule ^ - [E=ANUBIS_GUARD_OK:1]
RewriteCond %{{ENV:ANUBIS_GUARD_OK}} !=1
RewriteRule ^ - [F,END]
RequestHeader unset X-Plesk-Anubis-Origin
'''
