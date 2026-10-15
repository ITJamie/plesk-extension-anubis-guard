"""Server-wide GeoIP sources, immutable snapshots and recoverable activation."""
import base64
from contextlib import contextmanager
import fcntl
import glob
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from ag_core import GuardError
from ag_runtime import atomic, durable_unlink, execute, USER

KINDS = {"country": "GeoLite2-Country", "asn": "GeoLite2-ASN"}
MAX_FILE = 128 * 1024 * 1024
MAX_MATCHES = 1000
R2_HOST = "mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com"


def read_json(path, default):
    return json.loads(path.read_text()) if path.exists() else default


def checksum(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def configuration(data, saved_credentials):
    if not isinstance(data, dict) or set(data) - {"mode", "account_id", "license_key", "clear_key", "country_path", "asn_path"}:
        raise GuardError("Unexpected GeoIP settings")
    mode = data.get("mode")
    if not isinstance(mode, str) or mode not in ("disabled", "maxmind", "local"):
        raise GuardError("Choose disabled, MaxMind downloads or local databases")
    config = {"mode": mode}
    credentials = dict(saved_credentials)
    clear = data.get("clear_key", False)
    key = data.get("license_key", "")
    if type(clear) is not bool or not isinstance(key, str) or len(key) > 256 or any(ord(c) < 33 or ord(c) > 126 for c in key):
        raise GuardError("Invalid MaxMind license key")
    if clear and key:
        raise GuardError("Choose either replacing or clearing the license key")
    if clear:
        credentials = {}
    elif key:
        credentials["license_key"] = key
    account = data.get("account_id", "")
    if not isinstance(account, str) or len(account) > 20 or (account and not re.fullmatch(r"[1-9][0-9]*", account)):
        raise GuardError("MaxMind account ID must be a positive integer")
    if mode == "maxmind":
        if not account or not credentials.get("license_key"):
            raise GuardError("MaxMind downloads require an account ID and license key")
        config["account_id"] = account
    for kind in KINDS:
        value = data.get(kind + "_path", "")
        if not isinstance(value, str) or len(value) > 4096:
            raise GuardError("Invalid local database path")
        if mode == "local":
            if (not value.startswith("/") or "**" in value or any(c in value for c in "?[]\\")
                    or any(ord(c) < 32 or ord(c) == 127 for c in value)
                    or ".." in value.split("/") or value.endswith("/")):
                raise GuardError("Use absolute database file paths; only * wildcard matching is supported")
            config[kind + "_path"] = value
    return config, credentials


def inspect_database(path, kind):
    """Use AlmaLinux's native MaxMind reader, without parsing untrusted MMDB bytes in Python."""
    info = Path(path).stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE:
        raise GuardError("Database must be a regular MMDB file under 128 MiB")
    try:
        result = subprocess.run(["/usr/bin/mmdblookup", "--file", str(path), "--ip", "1.1.1.1", "--verbose"],
                                capture_output=True, text=True, timeout=15,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError("Cannot inspect MMDB; ensure AlmaLinux's mmdblookup utility is installed") from exc
    # An empty lookup can return nonzero despite valid metadata. Other failures
    # must not masquerade as a valid database just because metadata was printed.
    output = result.stdout + result.stderr
    if result.returncode and "Could not find an entry for this IP address" not in output:
        raise GuardError("MMDB validation failed")
    db_type = re.search(r"^\s*Type:\s+(\S+)\s*$", output, re.M)
    build = re.search(r"^\s*Build epoch:\s+(\d+)\b", output, re.M)
    allowed = (KINDS[kind], KINDS[kind].replace("GeoLite2", "GeoIP2"))
    if not db_type or db_type[1] not in allowed or not build or not 0 < int(build[1]) <= time.time() + 86400:
        raise GuardError("Invalid database type or build date for " + kind)
    return {"type": db_type[1], "build_epoch": int(build[1])}


def select_database(pattern, kind):
    candidates, warnings = [], []
    for index, filename in enumerate(glob.iglob(pattern)):
        if index >= MAX_MATCHES:
            raise GuardError("Database pattern matches more than 1000 files; narrow the pattern")
        path = Path(filename)
        try:
            metadata = inspect_database(path, kind)
            candidates.append((metadata["build_epoch"], str(path.absolute()), metadata))
        except (GuardError, OSError):
            warnings.append("Ignored invalid " + kind + " candidate: " + filename)
    if not candidates:
        raise GuardError("No valid " + kind + " database matches the configured path")
    _, filename, metadata = max(candidates, key=lambda item: (item[0], item[1]))
    return Path(filename), metadata, warnings


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urllib.parse.urlsplit(newurl)
        if (destination.scheme != "https" or destination.hostname not in ("download.maxmind.com", R2_HOST)
                or destination.username or destination.password or destination.port not in (None, 443)):
            raise GuardError("MaxMind returned an unsupported redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and destination.hostname != urllib.parse.urlsplit(req.full_url).hostname:
            redirected.remove_header("Authorization")
        return redirected


def download_database(kind, account, key, directory):
    edition = KINDS[kind]
    url = f"https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
    request = urllib.request.Request(url, headers={"Authorization": "Basic " + base64.b64encode(
        (account + ":" + key).encode()).decode(), "User-Agent": "Plesk-Anubis-Guard/0.6.0"})
    archive = directory / (kind + ".tar.gz")
    try:
        deadline = time.monotonic() + 120
        with urllib.request.build_opener(SafeRedirect()).open(request, timeout=20) as response, archive.open("xb") as handle:
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE or time.monotonic() > deadline:
                    raise GuardError("MaxMind download exceeded its size or time limit")
                handle.write(chunk)
        target = directory / (kind + ".mmdb")
        with tarfile.open(archive, "r:gz") as bundle:
            found, count, expanded = False, 0, 0
            for member in bundle:
                count += 1
                expanded += member.size
                name = PurePosixPath(member.name)
                if (count > 100 or expanded > MAX_FILE or member.size < 0 or name.is_absolute()
                        or ".." in name.parts or not (member.isdir() or member.isfile())):
                    raise GuardError("Unsafe MaxMind database archive")
                if member.isfile() and name.name == edition + ".mmdb":
                    if found:
                        raise GuardError("Duplicate database in MaxMind archive")
                    found = True
                    with bundle.extractfile(member) as source, target.open("xb") as out:
                        shutil.copyfileobj(source, out, 1024 * 1024)
            if not found:
                raise GuardError("MaxMind archive does not contain the required database")
        return target
    except urllib.error.HTTPError as exc:
        raise GuardError(f"MaxMind download returned HTTP {exc.code}; check account access and license key") from None
    except (urllib.error.URLError, OSError, tarfile.TarError, ValueError) as exc:
        # Never return response URLs (signed redirects) or authentication details.
        raise GuardError("MaxMind database download or extraction failed") from None


class GeoIP:
    def __init__(self, runtime):
        self.runtime = runtime
        self.root = runtime.state_path.parent / "geoip"
        self.state_path = self.root / "state.json"
        self.secret_path = self.root / "credentials.json"
        self.pending = self.root / "pending.json"
        self.job_path = self.root / "job.json"

    def initialize(self):
        self.root.mkdir(mode=0o711, parents=True, exist_ok=True)
        os.chmod(self.root, 0o711)

    def state(self):
        return read_json(self.state_path, {"config": {"mode": "disabled"}, "active": None,
                                          "last_check": None, "last_success": None, "warnings": []})

    def paths(self):
        active = self.state()["active"]
        return {kind: active[kind]["path"] for kind in KINDS} if active else None

    def status(self):
        state = self.state()
        job = read_json(self.job_path, {})
        return {**state, "has_license_key": bool(read_json(self.secret_path, {}).get("license_key")),
                "job": {k: job[k] for k in ("id", "status", "error", "finished") if k in job},
                "recovery_required": self.pending.exists()}

    @contextmanager
    def jobs_locked(self):
        self.initialize()
        with (self.root / "worker.lock").open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GuardError("A GeoIP update is already running; refresh status shortly") from None
            yield

    def enqueue(self, data=None):
        with self.jobs_locked():
            if self.pending.exists():
                raise GuardError("GeoIP recovery is required before another update")
            previous = read_json(self.job_path, {})
            if previous.get("status") in ("queued", "running"):
                raise GuardError("A GeoIP update is already queued; refresh status shortly")
            if data is None:
                config = self.state()["config"]
                credentials = read_json(self.secret_path, {})
            else:
                config, credentials = configuration(data, read_json(self.secret_path, {}))
            job = {"id": secrets.token_hex(16), "status": "queued", "config": config, "credentials": credentials}
            atomic(self.job_path, json.dumps(job))
            try:
                execute(["/usr/bin/systemctl", "start", "--no-block", "plesk-anubis-geoip.service"])
            except GuardError:
                atomic(self.job_path, json.dumps({"id": job["id"], "status": "failed", "error": "Could not start GeoIP worker"}))
                raise
        return {"ok": True, "job_id": job["id"]}

    def recover(self):
        """Caller holds the runtime apply lock; recovery may be repeated after a crash."""
        if not self.pending.exists():
            return
        transaction = read_json(self.pending, {})
        atomic(self.state_path, json.dumps(transaction["previous"]))
        atomic(self.secret_path, json.dumps(transaction["credentials"]))
        state, domains = self.runtime.read(), self.runtime.domains()
        for ident in transaction["affected"]:
            config, domain = state["domains"].get(ident), domains.get(ident)
            if config and config.get("enabled") and domain and domain["active"] and domain["hosting"] == "vrt_hst":
                self.runtime.prepare(ident, config)
                self.runtime.start(ident)
        durable_unlink(self.pending)

    def snapshot(self, config, credentials):
        if config["mode"] == "disabled":
            return None, []
        import grp
        group = grp.getgrnam(USER).gr_gid
        generations = self.root / "generations"
        generations.mkdir(mode=0o750, exist_ok=True)
        os.chmod(generations, 0o750)
        os.chown(generations, 0, group)
        warnings, active = [], {}
        with tempfile.TemporaryDirectory(prefix=".staging-", dir=generations) as temp:
            directory = Path(temp)
            os.chmod(directory, 0o750)
            os.chown(directory, 0, group)
            for kind in KINDS:
                if config["mode"] == "local":
                    source, metadata, ignored = select_database(config[kind + "_path"], kind)
                    warnings.extend(ignored)
                    target = directory / (kind + ".mmdb")
                    # Open once and copy bounded bytes; never follow an unchecked
                    # size change into an unbounded copy of a device/stream.
                    with source.open("rb") as inp, target.open("xb") as out:
                        if not stat.S_ISREG(os.fstat(inp.fileno()).st_mode):
                            raise GuardError("Database source changed while reading")
                        total = 0
                        while True:
                            chunk = inp.read(1024 * 1024)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > MAX_FILE:
                                raise GuardError("Database source exceeded the size limit")
                            out.write(chunk)
                else:
                    target = download_database(kind, config["account_id"], credentials["license_key"], directory)
                    source = Path(KINDS[kind] + " (MaxMind)")
                    metadata = inspect_database(target, kind)
                # Revalidate the snapshot, not just the mutable external source.
                if inspect_database(target, kind) != metadata:
                    raise GuardError("Database changed while taking its snapshot; retry refresh")
                os.chmod(target, 0o640)
                os.chown(target, 0, group)
                with target.open("rb") as handle:
                    os.fsync(handle.fileno())
                active[kind] = {**metadata, "source": str(source), "sha256": checksum(target)}
            generation = hashlib.sha256("".join(active[k]["sha256"] for k in KINDS).encode()).hexdigest()
            destination = generations / generation
            if not destination.exists():
                # Drop downloaded archives; only publish validated database files.
                for extra in directory.glob("*.tar.gz"):
                    extra.unlink()
                os.rename(directory, destination)
                directory.mkdir()  # TemporaryDirectory can clean its original path.
                fd = os.open(str(generations), os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            for kind in KINDS:
                active[kind]["path"] = str(destination / (kind + ".mmdb"))
        return active, warnings[:100]

    def activate(self, config, credentials, active, warnings):
        with self.runtime.locked():
            if any((self.runtime.state_path.parent / name).exists() for name in ("pending.json", "runtime-manager/pending.json")):
                raise GuardError("A site change requires recovery before GeoIP activation")
            self.recover()
            previous = self.state()
            old_credentials = read_json(self.secret_path, {})
            state, domains = self.runtime.read(), self.runtime.domains()
            affected = [ident for ident, site in state["domains"].items() if site.get("enabled")
                        and ident in domains and domains[ident]["active"] and domains[ident]["hosting"] == "vrt_hst"]
            changed = self.paths() != ({kind: active[kind]["path"] for kind in KINDS} if active else None)
            atomic(self.pending, json.dumps({"previous": previous, "credentials": old_credentials,
                                             "affected": affected if changed else []}))
            try:
                now = int(time.time())
                atomic(self.state_path, json.dumps({"config": config, "active": active, "warnings": warnings,
                                                   "last_check": now, "last_success": now}))
                atomic(self.secret_path, json.dumps(credentials))
                if changed:
                    for ident in affected:
                        self.runtime.prepare(ident, state["domains"][ident])
                        self.runtime.start(ident)
                durable_unlink(self.pending)
            except Exception:
                try:
                    self.recover()
                except Exception:
                    raise GuardError("GeoIP activation and rollback failed; recovery journal retained") from None
                raise GuardError("GeoIP activation failed; previous databases and services restored") from None
            # Keep the new and previous pair, excluding any generations retained
            # by a pending recovery. No user-supplied path can be deleted here.
            keep = {str(Path(item[k]["path"]).parent) for item in (active, previous["active"]) if item for k in KINDS}
            generations = self.root / "generations"
            if generations.exists():
                for child in generations.iterdir():
                    if re.fullmatch(r"[a-f0-9]{64}", child.name) and str(child) not in keep:
                        shutil.rmtree(child)

    def worker(self):
        try:
            with self.jobs_locked():
                with self.runtime.locked():
                    self.recover()
                job = read_json(self.job_path, {})
                if job.get("status") == "running":
                    # A prior worker died; recovery ran above. Its private payload
                    # can be retried without involving a browser POST.
                    job["status"] = "queued"
                if job.get("status") != "queued":
                    state = self.state()
                    interval = 86400 if state["config"]["mode"] == "maxmind" else 300
                    if state["config"]["mode"] == "disabled" or time.time() - (state["last_check"] or 0) < interval:
                        return {"ok": True}
                    job = {"id": secrets.token_hex(16), "config": state["config"],
                           "credentials": read_json(self.secret_path, {})}
                job["status"] = "running"
                atomic(self.job_path, json.dumps(job))
                try:
                    active, warnings = self.snapshot(job["config"], job["credentials"])
                    self.activate(job["config"], job["credentials"], active, warnings)
                    result = {"id": job["id"], "status": "succeeded", "finished": int(time.time())}
                except Exception as exc:
                    # Only our deliberate messages are safe for the panel. Never
                    # serialize raw download, path-parser or subprocess errors.
                    message = str(exc) if isinstance(exc, GuardError) else "GeoIP refresh failed; inspect server configuration"
                    result = {"id": job["id"], "status": "failed", "finished": int(time.time()), "error": message}
                    state = self.state()
                    state["last_check"] = int(time.time())
                    atomic(self.state_path, json.dumps(state))
                atomic(self.job_path, json.dumps(result))  # Erase private job payload.
                return {"ok": result["status"] == "succeeded"}
        except GuardError as exc:
            if "already running" in str(exc):
                return {"ok": True}
            raise
