"""Official stable releases and recoverable, server-wide runtime selection."""
from contextlib import contextmanager
import fcntl
import grp
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import tempfile
import time
import urllib.error
import urllib.request

from ag_core import GuardError, policy
from ag_payload import acquire, verify
from ag_runtime import atomic, durable_unlink, execute, USER, UnixConnection
from ag_geoip import GeoIP, read_json

REPO = "https://api.github.com/repos/TecharoHQ/anubis"
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def version_id(value):
    if not isinstance(value, str) or len(value) > 40 or not VERSION.fullmatch(value):
        raise GuardError("Choose an official stable numeric Anubis version")
    return value


def github(path, etag=None):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Plesk-Anubis-Guard", "X-GitHub-Api-Version": "2022-11-28"}
    if etag:
        headers["If-None-Match"] = etag
    try:
        # API endpoints are fixed by callers. Do not follow API redirects to a
        # renamed/foreign repository or process arbitrary URLs from release data.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        with urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(REPO + path, headers=headers), timeout=20) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                raise GuardError("GitHub release response is too large")
            return json.loads(body), response.headers.get("ETag")
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None, etag
        raise GuardError(f"GitHub returned HTTP {exc.code}; cached releases and runtimes remain available") from None
    except (OSError, ValueError):
        raise GuardError("Cannot fetch GitHub releases; cached releases and runtimes remain available") from None


def release_record(release):
    if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False:
        raise GuardError("Only published stable releases are supported")
    tag = release.get("tag_name", "")
    version = version_id(tag[1:] if isinstance(tag, str) and tag.startswith("v") else tag)
    if tag != "v" + version:
        raise GuardError("Unsupported release tag")
    filename = f"anubis-{version}-linux-amd64.tar.gz"
    if not isinstance(release.get("assets"), list):
        raise GuardError("Unexpected release assets")
    assets = [a for a in release["assets"] if isinstance(a, dict) and a.get("name") == filename]
    if len(assets) != 1:
        raise GuardError("Release has no unique Linux amd64 archive")
    asset = assets[0]
    digest = asset.get("digest")
    url = f"https://github.com/TecharoHQ/anubis/releases/download/v{version}/{filename}"
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise GuardError("Release asset has no verifiable GitHub SHA-256 digest")
    if asset.get("browser_download_url") != url or asset.get("state") != "uploaded":
        raise GuardError("Unexpected release asset URL or state")
    return {"version": version, "sha256": digest[7:], "url": url, "platform": "linux-amd64",
            "release_id": release.get("id"), "asset_id": asset.get("id"), "published": release.get("published_at"),
            "source": "github-release-api"}


class Versions:
    def __init__(self, runtime):
        from ag_runtime import MODULE
        self.runtime = runtime
        self.base = runtime.state_path.parent
        self.root = self.base / "runtime-manager"
        self.cache = self.base / "runtime"
        self.module = MODULE
        self.state_path = self.root / "state.json"
        self.pending = self.root / "pending.json"
        self.job_path = self.root / "job.json"
        self.catalog_path = self.root / "catalog.json"

    def pin(self):
        path = self.module / "runtime.lock.json"
        if not path.exists():
            path = Path(__file__).resolve().parents[2] / "runtime.lock.json"
        record = json.loads(path.read_text())
        version_id(record["version"])
        return record

    def state(self):
        return read_json(self.state_path, {"mode": "automatic", "version": self.pin()["version"],
                                           "previous": None, "legacy_version": self.pin()["version"]})

    def version(self):
        return version_id(self.state()["version"])

    def cached(self, version, check=True):
        version_id(version)
        directory = self.cache / version
        record = self.pin() if version == self.pin()["version"] else read_json(directory / ".release.json", {})
        if (not isinstance(record, dict) or record.get("version") != version
                or not isinstance(record.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", record["sha256"])):
            raise GuardError("Runtime is not downloaded or has no verified release record")
        if directory.is_symlink():
            raise GuardError("Runtime cache entry must not be a symlink")
        if check:
            try:
                verify(directory, read_json(directory / ".manifest.json", {}), record)
            except (OSError, ValueError, KeyError):
                raise GuardError("Cached runtime failed integrity verification") from None
        return record

    def link(self, version):
        version_id(version)
        tmp = self.cache / (".active-" + secrets.token_hex(8))
        try:
            os.symlink(version, tmp)
            os.replace(tmp, self.cache / "active")
            fd = os.open(str(self.cache), os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            tmp.unlink(missing_ok=True)

    def bootstrap(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.cache.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        os.chmod(self.cache, 0o755)
        pin = self.pin()
        atomic(self.cache / pin["version"] / ".release.json", json.dumps(pin))
        self.cached(self.version())
        if not self.state_path.exists():
            atomic(self.state_path, json.dumps(self.state()))
        self.link(self.version())
        atomic(self.cache / "launch", (Path(__file__).parent / "anubis-launch").read_bytes(), 0o755)

    def status(self):
        state = self.state()
        downloaded = []
        if self.cache.exists():
            for directory in self.cache.iterdir():
                if VERSION.fullmatch(directory.name) and not directory.is_symlink():
                    try:
                        self.cached(directory.name, check=False)
                        if (directory / ".manifest.json").is_file():
                            downloaded.append(directory.name)
                    except (GuardError, OSError, ValueError):
                        continue
        catalog = read_json(self.catalog_path, {"pages": {}})
        job = read_json(self.job_path, {})
        return {**state, "pinned_version": self.pin()["version"], "downloaded": sorted(downloaded, key=lambda v: tuple(map(int, v.split('.'))), reverse=True),
                "pages": catalog["pages"], "job": {k: job[k] for k in ("id", "status", "action", "error", "finished") if k in job},
                "recovery_required": self.pending.exists()}

    @contextmanager
    def jobs_locked(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.root / "worker.lock").open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GuardError("A runtime job is already running; refresh status shortly") from None
            yield

    def enqueue(self, data):
        if not isinstance(data, dict) or set(data) - {"action", "version", "mode", "page"}:
            raise GuardError("Unexpected runtime settings")
        action = data.get("action")
        if not isinstance(action, str) or action not in ("refresh", "download", "activate", "rollback"):
            raise GuardError("Unknown runtime action")
        request = {"action": action}
        if action == "refresh":
            page = data.get("page", 1)
            if type(page) is not int or not 1 <= page <= 100:
                raise GuardError("Release page must be from 1 to 100")
            request["page"] = page
        elif action == "download":
            request["version"] = version_id(data.get("version"))
        elif action == "activate":
            mode = data.get("mode")
            if mode not in ("automatic", "override"):
                raise GuardError("Choose automatic or override runtime selection")
            request["mode"] = mode
            if mode == "override":
                request["version"] = version_id(data.get("version"))
                self.cached(request["version"])
        with self.jobs_locked():
            if self.pending.exists():
                raise GuardError("Runtime recovery is required before another job")
            if read_json(self.job_path, {}).get("status") in ("queued", "running"):
                raise GuardError("A runtime job is already queued; refresh status shortly")
            job = {**request, "id": secrets.token_hex(16), "status": "queued"}
            atomic(self.job_path, json.dumps(job))
            try:
                execute(["/usr/bin/systemctl", "start", "--no-block", "plesk-anubis-runtime.service"])
            except GuardError:
                atomic(self.job_path, json.dumps({**job, "status": "failed", "error": "Could not start runtime worker"}))
                raise
        return {"ok": True, "job_id": job["id"]}

    def refresh(self, page):
        catalog = read_json(self.catalog_path, {"pages": {}})
        previous = catalog["pages"].get(str(page), {})
        releases, etag = github(f"/releases?per_page=50&page={page}", previous.get("etag"))
        if releases is not None:
            if not isinstance(releases, list) or len(releases) > 50:
                raise GuardError("Unexpected GitHub release list")
            records = []
            for release in releases:
                try:
                    records.append(release_record(release))
                except GuardError:
                    continue
            catalog["pages"][str(page)] = {"releases": records, "etag": etag, "has_more": len(releases) == 50}
        elif not previous:
            raise GuardError("GitHub returned an empty cache response")
        catalog["pages"][str(page)]["checked"] = int(time.time())
        atomic(self.catalog_path, json.dumps(catalog))

    def download(self, version):
        version_id(version)
        if version == self.pin()["version"]:
            record = self.pin()
        else:
            if (self.cache / version).exists():
                return self.cached(version)
            release, _ = github("/releases/tags/v" + version)
            record = release_record(release)
            if record["version"] != version:
                raise GuardError("GitHub returned a different release")
        try:
            acquire(self.cache, self.module, record)
        except (OSError, ValueError):
            raise GuardError("Runtime download or integrity verification failed; active runtime is unchanged") from None
        atomic(self.cache / version / ".release.json", json.dumps(record))
        return record

    def eligible(self):
        domains = self.runtime.domains()
        return {ident: config for ident, config in self.runtime.read()["domains"].items() if config.get("enabled")
                and ident in domains and domains[ident]["active"] and domains[ident]["hosting"] == "vrt_hst"}

    def migrate_legacy(self, ident):
        legacy = self.base / str(ident) / "data/challenges.bdb"
        if not legacy.exists():
            return
        # Stop before moving a memory-mapped bbolt file; never copy a live DB.
        self.runtime.stop(ident)
        version = version_id(self.state().get("legacy_version", self.pin()["version"]))
        destination = legacy.parent / ("runtime-" + version)
        destination.mkdir(mode=0o700, exist_ok=True)
        os.chown(destination, pwd.getpwnam(USER).pw_uid, grp.getgrnam(USER).gr_gid)
        if (destination / "challenges.bdb").exists():
            raise GuardError("Legacy challenge database migration conflicts with an existing store")
        os.rename(legacy, destination / "challenges.bdb")
        fd = os.open(str(legacy.parent), os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def probe(self, version):
        from ag_runtime import RUN
        self.cached(version)
        binary = self.cache / version / "bin/anubis"
        with binary.open("rb") as handle:
            elf = handle.read(20)
        if elf[:6] != b"\x7fELF\x02\x01" or elf[18:20] != b"\x3e\x00":
            raise GuardError("Candidate is not a Linux amd64 ELF runtime")
        properties = ["--property=User=" + USER, "--property=Group=nginx", "--property=SupplementaryGroups=" + USER,
                      "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
                      "--property=PrivateTmp=yes", "--property=CapabilityBoundingSet="]
        report = execute(["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", *properties,
                          str(binary), "--version"], timeout=20)
        if not re.search(r"\bv?" + re.escape(version) + r"\b", report):
            raise GuardError("Candidate runtime reports a different version")
        account, group = pwd.getpwnam(USER), grp.getgrnam(USER)
        sites = self.eligible() or {"1": {"enabled": True, "paths": [], "ips": []}}
        for ident, config in sites.items():
            with tempfile.TemporaryDirectory(prefix=".probe-", dir=RUN) as temp:
                directory = Path(temp)
                os.chmod(directory, 0o750)
                os.chown(directory, account.pw_uid, group.gr_gid)
                unit = "plesk-anubis-probe-" + secrets.token_hex(8)
                probe_policy = policy({k: config[k] for k in ("enabled", "paths", "ips", "challenge_mode", "difficulty") if k in config},
                                      str(directory / "challenges.bdb"), str(directory / "metrics.sock"), GeoIP(self.runtime).paths())
                atomic(directory / "policy.json", json.dumps(probe_policy), 0o644)
                atomic(directory / "signing-key", secrets.token_hex(32) + "\n", 0o640)
                os.chown(directory / "signing-key", 0, group.gr_gid)
                values = self.runtime.service_environment(ident)
                values.update({"BIND": str(directory / "anubis.sock"), "POLICY_FNAME": str(directory / "policy.json"),
                               "ED25519_PRIVATE_KEY_HEX_FILE": str(directory / "signing-key")})
                atomic(directory / "environment", "".join(f'{k}="{v}"\n' for k, v in values.items()))
                try:
                    execute(["/usr/bin/systemd-run", "--quiet", "--collect", "--unit=" + unit, *properties,
                             "--property=ReadWritePaths=" + temp, "--property=EnvironmentFile=" + str(directory / "environment"),
                             str(binary)], timeout=15)
                    deadline, ready = time.monotonic() + 8, False
                    while time.monotonic() < deadline:
                        connection = UnixConnection(directory / "metrics.sock", timeout=0.5)
                        try:
                            connection.request("GET", "/healthz")
                            ready = connection.getresponse().status == 200
                        except (OSError, http.client.HTTPException):
                            pass
                        finally:
                            connection.close()
                        if ready:
                            image = UnixConnection(directory / "anubis.sock", timeout=0.5)
                            try:
                                image.request("GET", "/.within.website/x/cmd/anubis/static/img/pensive.webp")
                                response = image.getresponse()
                                header = response.read(12)
                                ready = response.status == 200 and header[:4] == b"RIFF" and header[8:12] == b"WEBP"
                            except (OSError, http.client.HTTPException):
                                ready = False
                            finally:
                                image.close()
                        if ready:
                            break
                        time.sleep(0.2)
                    if not ready:
                        raise GuardError(f"Runtime {version} failed the policy startup probe for domain {ident}")
                finally:
                    try:
                        execute(["/usr/bin/systemctl", "stop", unit], timeout=15)
                    except GuardError:
                        pass

    def recover(self):
        # Caller holds the shared apply lock; restoration never changes nginx.
        if not self.pending.exists():
            return
        transaction = read_json(self.pending, {})
        previous = transaction["previous"]
        self.cached(previous["version"])
        atomic(self.state_path, json.dumps(previous))
        self.link(previous["version"])
        sites = self.eligible()
        for ident in transaction["affected"]:
            if ident in sites:
                self.runtime.stop(ident)
                self.migrate_legacy(ident)
                self.runtime.prepare(ident, sites[ident])
                self.runtime.start(ident)
        durable_unlink(self.pending)

    def activate(self, mode, version=None, force=False):
        if mode not in ("automatic", "override"):
            raise GuardError("Invalid runtime selection mode")
        version = self.pin()["version"] if mode == "automatic" else version_id(version)
        if mode == "automatic":
            self.download(version)
        self.cached(version)
        with self.runtime.locked():
            self._activate_locked(mode, version, force)

    def _activate_locked(self, mode, version, force=False, probe=True):
        # Internal installer path: caller holds the shared apply lock and has
        # verified the cache and probed this exact candidate under that lock.
        if (self.base / "pending.json").exists() or (self.base / "geoip/pending.json").exists():
            raise GuardError("Another configuration change requires recovery before switching runtimes")
        if self.pending.exists():
            raise GuardError("Runtime recovery is required before switching runtimes")
        previous = self.state()
        changed = version != previous["version"] or force
        if changed and probe:
            self.probe(version)
        sites = self.eligible() if changed else {}
        transaction = {"previous": previous, "affected": list(sites)}
        atomic(self.pending, json.dumps(transaction))
        try:
            state = {**previous, "mode": mode, "version": version,
                     "previous": previous["version"] if version != previous["version"] else previous.get("previous")}
            atomic(self.state_path, json.dumps(state))
            self.link(version)
            for ident, config in sites.items():
                self.runtime.stop(ident)
                self.migrate_legacy(ident)
                self.runtime.prepare(ident, config)
                self.runtime.start(ident)
            durable_unlink(self.pending)
        except Exception:
            try:
                self.recover()
            except Exception:
                raise GuardError("Runtime activation and rollback failed; recovery journal retained") from None
            raise GuardError("Runtime activation failed; previous runtime and services restored") from None

    def worker(self):
        try:
            with self.jobs_locked():
                with self.runtime.locked():
                    self.recover()
                job = read_json(self.job_path, {})
                if job.get("status") not in ("queued", "running"):
                    return {"ok": True}
                job["status"] = "running"
                atomic(self.job_path, json.dumps(job))
                try:
                    action = job["action"]
                    if action == "refresh":
                        self.refresh(job["page"])
                    elif action == "download":
                        self.download(job["version"])
                    elif action == "activate":
                        self.activate(job["mode"], job.get("version"))
                    elif action == "rollback":
                        previous = self.state().get("previous")
                        if not previous:
                            raise GuardError("There is no previous runtime to roll back to")
                        self.activate("override", previous)
                    job["status"] = "succeeded"
                except Exception as exc:
                    job["status"] = "failed"
                    job["error"] = str(exc) if isinstance(exc, GuardError) else "Runtime job failed; inspect its service journal"
                job["finished"] = int(time.time())
                atomic(self.job_path, json.dumps(job))
                return {"ok": job["status"] == "succeeded"}
        except GuardError as exc:
            if "already running" in str(exc):
                return {"ok": True}
            raise
