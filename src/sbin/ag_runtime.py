"""Privileged operations. Paths and commands are fixed; UI input is settings only."""
import copy
import fcntl
import grp
import http.client
import json
import os
from pathlib import Path
import platform
import pwd
import secrets
import shutil
import socket
import subprocess
import time

from ag_core import GuardError, Transformer, apache_guard, domain_id, ingress, policy, settings
from ag_payload import acquire

MODULE = Path("/usr/local/psa/admin/sbin/modules/anubis-guard")
ROOT = Path("/var/lib/plesk-anubis")
RUN = Path("/run/plesk-anubis")
NGINX = Path("/etc/nginx/conf.d/zz-anubis-guard.conf")
USER = "plesk-anubis"
UNIT = "plesk-anubis@{}.service"


def atomic(path, data, mode=0o600):
    path = Path(path)
    tmp = path.with_name(path.name + "." + secrets.token_hex(8) + ".new")
    # Root-owned parents; never follow a preexisting temporary symlink.
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb" if isinstance(data, bytes) else "w") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        directory = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if tmp.exists():
            tmp.unlink()


def execute(args, timeout=120):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError(f"Cannot run {args[0]}: {exc}") from exc
    if result.returncode:
        # Do not return full generated config or secret-bearing env files to panel.
        raise GuardError(f"{Path(args[0]).name} failed (exit {result.returncode}); inspect the server journal")
    return result.stdout


def durable_unlink(path):
    path.unlink()
    directory = os.open(str(path.parent), os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def install_artwork():
    """Publish original, extension-owned icons where nginx can read them."""
    group = grp.getgrnam("nginx").gr_gid
    source = Path(__file__).parent / "assets/generic-v1"
    target = ROOT / "assets/generic-v1"
    for directory in (target.parent, target):
        directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        os.chmod(directory, 0o750)
        os.chown(directory, 0, group)
    for name in ("happy", "pensive", "reject"):
        path = target / (name + ".webp")
        body = (source / (name + ".webp")).read_bytes()
        if body[:4] != b"RIFF" or body[8:12] != b"WEBP":
            raise GuardError("Invalid packaged challenge image")
        if not path.exists() or path.read_bytes() != body:
            atomic(path, body, 0o640)
        os.chmod(path, 0o640)
        os.chown(path, 0, group)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=2):
        super().__init__("localhost", timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def healthy(ident, timeout=2):
    connection = UnixConnection(RUN / str(ident) / "metrics.sock", timeout=timeout)
    try:
        connection.request("GET", "/healthz")
        return connection.getresponse().status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


class Runtime:
    def __init__(self):
        self.state_path = ROOT / "state.json"

    def read(self):
        if not self.state_path.exists():
            return {"version": 1, "domains": {}}
        data = json.loads(self.state_path.read_text())
        if data.get("version") != 1 or not isinstance(data.get("domains"), dict):
            raise GuardError("Unsupported or damaged extension state; restore its backup")
        return data

    def write(self, state):
        atomic(self.state_path, json.dumps(state, indent=2) + "\n")

    def locked(self):
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        handle = (ROOT / "apply.lock").open("a")
        # Avoid deadlocking configuration hooks: render/status deliberately do not lock.
        deadline = time.monotonic() + 15
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return handle
            except BlockingIOError:
                if time.monotonic() > deadline:
                    handle.close()
                    raise GuardError("Another configuration change is running; try again shortly")
                time.sleep(0.1)

    def domains(self):
        rows = execute(["/usr/sbin/plesk", "db", "-N", "-B", "-e",
                        "SELECT id,name,htype,status FROM domains ORDER BY id"])
        result = {}
        for row in rows.splitlines():
            ident, name, hosting, status = row.split("\t")
            domain_id(ident)
            if not name or len(name) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-._" for c in name.lower()):
                raise GuardError("Unsupported domain name in Plesk")
            result[ident] = {"id": int(ident), "name": name, "hosting": hosting, "active": status == "0"}
        return result

    def status(self, ids=None):
        allowed = None
        if ids is not None:
            if not isinstance(ids, list) or len(ids) > 10000:
                raise GuardError("Expected a bounded list of Plesk domain IDs")
            allowed = {str(domain_id(ident)) for ident in ids}
        state = self.read()
        output = []
        for ident, domain in self.domains().items():
            if allowed is not None and ident not in allowed:
                continue
            config = state["domains"].get(ident, {})
            enabled = config.get("enabled", False)
            output.append({**domain, "enabled": enabled,
                           "paths": config.get("paths", []), "ips": config.get("ips", []),
                           "challenge_mode": config.get("challenge_mode", "adaptive"),
                           "difficulty": config.get("difficulty", 2),
                           "failure_mode": config.get("failure_mode", "closed"),
                           "protection_scope": config.get("protection_scope", "all"),
                           "included_paths": config.get("included_paths", []),
                           "image_style": config.get("image_style", "original"),
                           "healthy": healthy(ident) if enabled else None,
                           "last_error": config.get("last_error", "")})
        from ag_versions import Versions
        return {"domains": output, "runtime_version": Versions(self).version()}

    def reconfigure(self, name):
        # The panel can itself be proxied through nginx on :443. A hard restart
        # here drops the API connection that is waiting for this operation.
        execute(["/usr/local/psa/admin/sbin/httpdmng", "--reconfigure-domain", name, "-no-restart"], timeout=180)
        execute(["/usr/sbin/nginx", "-t"])
        # Apache may be absent or stopped on nginx/PHP-FPM installations. Reload
        # only a running service, and activate its origin guard before the edge.
        apache_active = Path("/usr/sbin/httpd").is_file() and execute([
            "/usr/bin/systemctl", "show", "httpd", "--property=ActiveState", "--value"]).strip() == "active"
        if apache_active:
            execute(["/usr/sbin/httpd", "-t"])
            execute(["/usr/bin/systemctl", "reload", "httpd"])
        execute(["/usr/bin/systemctl", "reload", "nginx"])

    def prepare(self, ident, config):
        from ag_geoip import GeoIP
        from ag_versions import Versions
        versions = Versions(self)
        versions.migrate_legacy(ident)
        if config.get("image_style") == "generic":
            install_artwork()
        account = pwd.getpwnam(USER)
        group = grp.getgrnam(USER)
        directory = ROOT / str(ident)
        directory.mkdir(mode=0o750, exist_ok=True)
        os.chown(directory, 0, group.gr_gid)
        os.chmod(directory, 0o750)
        storage = directory / "data"
        storage.mkdir(mode=0o700, exist_ok=True)
        os.chown(storage, account.pw_uid, group.gr_gid)
        os.chmod(storage, 0o700)
        storage = storage / ("runtime-" + versions.version())
        storage.mkdir(mode=0o700, exist_ok=True)
        os.chown(storage, account.pw_uid, group.gr_gid)
        os.chmod(storage, 0o700)
        RUN.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(RUN, 0o755)
        runtime = RUN / str(ident)
        runtime.mkdir(mode=0o770, parents=True, exist_ok=True)
        os.chown(runtime, 0, grp.getgrnam("nginx").gr_gid)
        # mkdir's mode is filtered by Plesk's umask, and exist_ok does not repair
        # older directories. The unprivileged service needs group write access.
        os.chmod(runtime, 0o770)
        policy_text = json.dumps(policy(
            {k: config[k] for k in ("enabled", "paths", "ips", "challenge_mode", "difficulty") if k in config},
            str(storage / "challenges.bdb"), str(runtime / "metrics.sock"),
            geoip=GeoIP(self).paths()), indent=2) + "\n"
        policies = directory / "policies"
        policies.mkdir(mode=0o750, exist_ok=True)
        os.chmod(policies, 0o750)
        os.chown(policies, 0, group.gr_gid)
        versioned_policy = policies / (versions.version() + ".json")
        atomic(versioned_policy, policy_text, 0o640)
        os.chown(versioned_policy, 0, group.gr_gid)
        # Keep the diagnostic path while running instances watch their own
        # version-specific policy, never another runtime's database namespace.
        atomic(directory / "policy.json", policy_text, 0o640)
        os.chown(directory / "policy.json", 0, group.gr_gid)
        key = directory / "signing-key"
        if not key.exists():
            # Anubis accepts the 32-byte ed25519 seed, hex encoded.
            atomic(key, secrets.token_hex(32) + "\n", 0o640)
            os.chown(key, 0, group.gr_gid)
        values = self.service_environment(ident)
        atomic(directory / "environment", "".join(f'{k}="{v}"\n' for k, v in values.items()), 0o640)
        os.chown(directory / "environment", 0, group.gr_gid)

    def service_environment(self, ident):
        from ag_versions import Versions
        version = Versions(self).version()
        directory, runtime = ROOT / str(ident), RUN / str(ident)
        return {
            "BIND": str(runtime / "anubis.sock"), "BIND_NETWORK": "unix", "SOCKET_MODE": "0660",
            "TARGET": "unix://" + str(runtime / "router.sock"),
            "POLICY_FNAME": str(directory / "policies" / (version + ".json")),
            "ED25519_PRIVATE_KEY_HEX_FILE": str(directory / "signing-key"),
            "ANUBIS_RUNTIME_VERSION": version,
            "COOKIE_PREFIX": f"plesk-anubis-{ident}", "COOKIE_DYNAMIC_DOMAIN": "false",
            "COOKIE_PARTITIONED": "false", "DYNAMIC_COOKIE_SUFFIX": "true",
            "SLOG_LEVEL": "INFO", "PUBLIC_URL": "",
        }

    def routing(self, state):
        atomic(NGINX, "# Anubis private domain routers\n"
               "map $http_upgrade $anubis_guard_connection { default upgrade; '' close; }\n" + "\n".join(
            ingress(ident) for ident, config in sorted(state["domains"].items()) if config.get("enabled")), 0o644)
        # systemd-tmpfiles runs before nginx at boot; /run is volatile.
        atomic(Path("/etc/tmpfiles.d/plesk-anubis.conf"), f"d {RUN} 0755 root root -\n" + "".join(
            f"d {RUN}/{domain_id(ident)} 0770 root nginx -\n"
            for ident, config in sorted(state["domains"].items()) if config.get("enabled")), 0o644)

    def start(self, ident):
        unit = UNIT.format(domain_id(ident))
        execute(["/usr/bin/systemctl", "restart", unit], timeout=15)
        deadline = time.monotonic() + 8
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if healthy(ident, timeout=min(1, remaining)):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            status = execute(["/usr/bin/systemctl", "show", unit, "--property=ActiveState",
                              "--property=SubState", "--property=ExecMainStatus"], timeout=min(2, remaining))
            values = dict(line.split("=", 1) for line in status.splitlines() if "=" in line)
            if values.get("ActiveState") in ("failed", "inactive") or values.get("SubState") == "auto-restart":
                raise GuardError(f"Anubis exited during startup (status {values.get('ExecMainStatus', 'unknown')}). "
                                 f"Inspect: journalctl -u {unit} -n 50 --no-pager")
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        raise GuardError(f"Anubis did not become healthy within 8 seconds. "
                         f"Inspect: journalctl -u {unit} -n 50 --no-pager")

    def stop(self, ident):
        execute(["/usr/bin/systemctl", "stop", UNIT.format(ident)])

    def restore(self, ident, previous, domain, routing_changed=True):
        self.write(previous)
        old = previous["domains"].get(ident)
        if old and old.get("enabled"):
            self.prepare(ident, old)
            self.start(ident)
        if routing_changed:
            self.routing(previous)
            self.reconfigure(domain["name"])
        if not old or not old.get("enabled"):
            self.stop(ident)

    def apply(self, ident, submitted):
        ident = str(domain_id(ident))
        clean = settings(submitted)
        with self.locked():
            if any((ROOT / name).exists() for name in ("pending.json", "geoip/pending.json", "runtime-manager/pending.json")):
                raise GuardError("An interrupted change needs recovery; run the reconcile helper before saving again")
            domains = self.domains()
            if ident not in domains:
                raise GuardError("Domain no longer exists")
            domain = domains[ident]
            if clean["enabled"] and (domain["hosting"] != "vrt_hst" or not domain["active"]):
                raise GuardError("Only active domains with physical web hosting can be enabled")
            previous = self.read()
            state = copy.deepcopy(previous)
            old = previous["domains"].get(ident, {})
            config = {**old, **clean, "name": domain["name"], "last_error": "",
                      "origin_key": old.get("origin_key") or secrets.token_hex(32)}
            state["domains"][ident] = config
            # Durable journal allows the timer to recover an interrupted apply.
            transaction = {"id": ident, "previous": previous, "domain": domain, "routing_changed": False}
            atomic(ROOT / "pending.json", json.dumps(transaction))
            routing_changed = False
            try:
                if clean["enabled"]:
                    self.prepare(ident, config)
                    self.start(ident)
                # Mark before changing routing/state so crash recovery always
                # restores potentially touched web configuration.
                transaction["routing_changed"] = True
                atomic(ROOT / "pending.json", json.dumps(transaction))
                routing_changed = True
                self.write(state)
                self.routing(state)
                self.reconfigure(domain["name"])
                if not clean["enabled"]:
                    self.stop(ident)
                durable_unlink(ROOT / "pending.json")
            except Exception as exc:
                try:
                    self.restore(ident, previous, domain, routing_changed)
                    restored = self.read()
                    restored["domains"].setdefault(ident, {"enabled": False, "paths": [], "ips": [], "name": domain["name"]})["last_error"] = str(exc)
                    self.write(restored)
                    durable_unlink(ROOT / "pending.json")
                except Exception as rollback:
                    raise GuardError("Apply and rollback failed; recovery journal retained. Inspect the server journal before retrying") from rollback
                raise GuardError(str(exc)) from exc
        return {"ok": True}

    def render(self, ident, template, content, origins=None):
        ident = str(domain_id(ident))
        config = self.read()["domains"].get(ident, {})
        if not config.get("enabled"):
            return content
        if template == "apache":
            return apache_guard(config["origin_key"])
        if template != Transformer.TEMPLATE:
            raise GuardError("Unsupported template")
        return Transformer(ident, config["origin_key"], read_include=lambda p: Path(p).read_text(),
                           origins=origins, failure_mode=config.get("failure_mode", "closed"),
                           scope=config.get("protection_scope", "all"),
                           included_paths=config.get("included_paths", []),
                           image_style=config.get("image_style", "original"),
                           artwork_root=str(ROOT / "assets/generic-v1")).transform(content)

    def reconcile(self):
        from ag_geoip import GeoIP
        from ag_versions import Versions
        with self.locked():
            Versions(self).recover()
            GeoIP(self).recover()
            pending = ROOT / "pending.json"
            if pending.exists():
                transaction = json.loads(pending.read_text())
                domains = self.domains()
                domain = domains.get(transaction["id"])
                if domain:
                    self.restore(transaction["id"], transaction["previous"], domain,
                                 transaction.get("routing_changed", True))
                else:
                    self.write(transaction["previous"])
                durable_unlink(pending)
            state = self.read()
            domains = self.domains()
            dirty = False
            for ident, config in list(state["domains"].items()):
                domain = domains.get(ident)
                if domain is None:
                    self.stop(ident)
                    del state["domains"][ident]
                    # IDs are authoritative; never derive deletion paths from names.
                    shutil.rmtree(ROOT / str(domain_id(ident)), ignore_errors=True)
                    dirty = True
                elif config.get("enabled"):
                    try:
                        self.prepare(ident, config)
                        if not domain["active"] or domain["hosting"] != "vrt_hst":
                            self.stop(ident)
                        elif not healthy(ident):
                            self.start(ident)
                        if domain["name"] != config["name"]:
                            config["name"] = domain["name"]
                            dirty = True
                            self.reconfigure(domain["name"])
                    except GuardError as exc:
                        config["last_error"] = str(exc)
                        dirty = True
            if dirty:
                self.write(state)
                self.routing(state)
                execute(["/usr/sbin/nginx", "-t"])
                execute(["/usr/bin/systemctl", "reload", "nginx"])
        return {"ok": True}

    def uninstall(self):
        from ag_geoip import GeoIP
        for unit in ("plesk-anubis-runtime.timer", "plesk-anubis-runtime.service"):
            if (Path("/etc/systemd/system") / unit).exists():
                execute(["/usr/bin/systemctl", "stop", unit])
        if Path("/etc/systemd/system/plesk-anubis-runtime.timer").exists():
            execute(["/usr/bin/systemctl", "disable", "plesk-anubis-runtime.timer"])
        if Path("/etc/systemd/system/plesk-anubis-geoip.timer").exists():
            execute(["/usr/bin/systemctl", "disable", "--now", "plesk-anubis-geoip.timer"])
        if Path("/etc/systemd/system/plesk-anubis-geoip.service").exists():
            execute(["/usr/bin/systemctl", "stop", "plesk-anubis-geoip.service"])
        # Every disable must complete before the extension hook can be removed.
        self.reconcile()
        for ident, config in self.read()["domains"].copy().items():
            if config.get("enabled"):
                self.apply(ident, {"enabled": False, "paths": config.get("paths", []), "ips": config.get("ips", [])})
        execute(["/usr/bin/systemctl", "disable", "--now", "plesk-anubis-reconcile.timer"])
        NGINX.unlink(missing_ok=True)
        for name in ("plesk-anubis@.service", "plesk-anubis-reconcile.service", "plesk-anubis-reconcile.timer",
                     "plesk-anubis-geoip.service", "plesk-anubis-geoip.timer",
                     "plesk-anubis-runtime.service", "plesk-anubis-runtime.timer"):
            (Path("/etc/systemd/system") / name).unlink(missing_ok=True)
        Path("/etc/tmpfiles.d/plesk-anubis.conf").unlink(missing_ok=True)
        execute(["/usr/bin/systemctl", "daemon-reload"])
        geo = GeoIP(self)
        geo.secret_path.unlink(missing_ok=True)
        geo.job_path.unlink(missing_ok=True)
        (ROOT / "runtime-manager/job.json").unlink(missing_ok=True)
        for pattern in ("credentials.json.*.new", "job.json.*.new", "pending.json.*.new"):
            for leftover in geo.root.glob(pattern):
                leftover.unlink()
        # Retain settings and signing/challenge data for reinstall/recovery.
        return {"ok": True}


def preflight():
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "almalinux" or not release.get("VERSION_ID", "").strip('"').startswith("9."):
        raise GuardError("V1 supports AlmaLinux 9 only")
    if platform.machine() != "x86_64":
        raise GuardError("V1 supports x86_64 only")
    version = Path("/usr/local/psa/version").read_text().split()[0]
    if tuple(map(int, version.split("."))) < (18, 0, 81):
        raise GuardError("Plesk 18.0.81 or newer is required")
    if not Path("/etc/nginx/nginx.conf").is_file():
        raise GuardError("The Plesk nginx component is required")
    if not Path("/usr/bin/mmdblookup").is_file():
        raise GuardError("GeoIP validation requires AlmaLinux's libmaxminddb package (mmdblookup)")
    if Path("/sys/fs/selinux/enforce").exists() and Path("/sys/fs/selinux/enforce").read_text().strip() == "1":
        raise GuardError("SELinux enforcing requires a reviewed local policy; this release does not change SELinux")
    execute(["/usr/bin/systemctl", "is-active", "nginx"])
    return {"ok": True}


def install_service_units(binary):
    unit = f'''[Unit]
Description=Anubis protection for Plesk domain %i
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
User={USER}
Group=nginx
SupplementaryGroups={USER}
EnvironmentFile={ROOT}/%i/environment
ExecStart={binary}
Restart=always
RestartSec=2s
UMask=0007
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={ROOT}/%i/data {RUN}/%i
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
TimeoutStopSec=30
'''
    atomic(Path("/etc/systemd/system/plesk-anubis@.service"), unit, 0o644)
    atomic(Path("/etc/systemd/system/plesk-anubis-reconcile.service"), f'''[Unit]
Description=Reconcile Anubis protection with Plesk domains
After=network.target
Before=nginx.service

[Service]
Type=oneshot
ExecStart={MODULE}/anubis-guard reconcile
TimeoutStartSec=600
''', 0o644)
    atomic(Path("/etc/systemd/system/plesk-anubis-reconcile.timer"), '''[Unit]
Description=Reconcile Plesk Anubis instances after reboot and domain changes

[Timer]
OnBootSec=5s
OnUnitInactiveSec=60s
Unit=plesk-anubis-reconcile.service

[Install]
WantedBy=timers.target
''', 0o644)
    atomic(Path("/etc/systemd/system/plesk-anubis-geoip.service"), f'''[Unit]
Description=Refresh Anubis GeoIP databases
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={MODULE}/anubis-guard geoip-worker
TimeoutStartSec=0
UMask=0077
''', 0o644)
    atomic(Path("/etc/systemd/system/plesk-anubis-geoip.timer"), '''[Unit]
Description=Check Anubis GeoIP database sources

[Timer]
OnBootSec=2min
OnUnitInactiveSec=5min
Unit=plesk-anubis-geoip.service

[Install]
WantedBy=timers.target
''', 0o644)
    atomic(Path("/etc/systemd/system/plesk-anubis-runtime.service"), f'''[Unit]
Description=Manage Anubis runtime versions
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={MODULE}/anubis-guard runtime-worker
TimeoutStartSec=0
UMask=0077
''', 0o644)
    atomic(Path("/etc/systemd/system/plesk-anubis-runtime.timer"), '''[Unit]
Description=Resume interrupted Anubis runtime jobs

[Timer]
OnBootSec=2min
OnUnitInactiveSec=5min
Unit=plesk-anubis-runtime.service

[Install]
WantedBy=timers.target
''', 0o644)


def install():
    preflight()
    ROOT.mkdir(mode=0o711, exist_ok=True)
    lock = json.loads((MODULE / "runtime.lock.json").read_text())
    # Fetch/verify before touching services or website routing. Reuse immutable
    # cached versions. Offline bundles take the same verification path.
    binary = acquire(ROOT / "runtime", MODULE, lock)
    try:
        pwd.getpwnam(USER)
    except KeyError:
        execute(["/usr/sbin/useradd", "--system", "--user-group", "--home-dir", "/nonexistent", "--shell", "/sbin/nologin", USER])
    ROOT.mkdir(mode=0o700, exist_ok=True)
    # Services need traversal but cannot list or modify the root state directory.
    os.chmod(ROOT, 0o711)
    install_artwork()
    RUN.mkdir(mode=0o755, exist_ok=True)
    os.chmod(RUN, 0o755)
    from ag_versions import Versions
    runtime = Runtime()
    versions = Versions(runtime)
    # Probes run before replacing the service launcher or production policies.
    # Overrides are never silently replaced by the extension's pinned default.
    with runtime.locked():
        versions.recover()
        from ag_geoip import GeoIP
        GeoIP(runtime).recover()
        if (ROOT / "pending.json").exists():
            raise GuardError("A site change needs reconciliation before upgrading runtime services")
        versions.bootstrap()
        selection = versions.state()
        desired = versions.pin()["version"] if selection["mode"] == "automatic" else selection["version"]
        versions.probe(desired)
        for ident, config in runtime.read()["domains"].items():
            if config.get("enabled"):
                environment = ROOT / ident / "environment"
                if environment.exists() and "ANUBIS_RUNTIME_VERSION=" not in environment.read_text():
                    text = environment.read_text() + f'ANUBIS_RUNTIME_VERSION="{versions.version()}"\n'
                    atomic(environment, text, 0o640)
                    os.chown(environment, 0, grp.getgrnam(USER).gr_gid)
        install_service_units(versions.cache / "launch")
        atomic(Path("/etc/tmpfiles.d/plesk-anubis.conf"), f"d {RUN} 0755 root root -\n", 0o644)
        if not runtime.state_path.exists():
            runtime.write({"version": 1, "domains": {}})
        runtime.routing(runtime.read())
        execute(["/usr/bin/systemctl", "daemon-reload"])
        versions._activate_locked(selection["mode"], desired, force=True, probe=False)
        # Prepare suspended enabled sites without starting them.
        for ident, config in runtime.read()["domains"].items():
            if config.get("enabled") and ident not in versions.eligible():
                runtime.prepare(ident, config)
    execute(["/usr/bin/systemctl", "enable", "--now", "plesk-anubis-reconcile.timer"])
    runtime.reconcile()
    execute(["/usr/bin/systemctl", "enable", "--now", "plesk-anubis-geoip.timer"])
    execute(["/usr/bin/systemctl", "enable", "--now", "plesk-anubis-runtime.timer"])
    return {"ok": True}
