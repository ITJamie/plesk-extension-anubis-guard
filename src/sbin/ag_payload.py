"""Pinned release acquisition shared by the installer and offline ZIP builder."""
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import urllib.request
import urllib.parse
import time

MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme != "https" or target.hostname not in (
                "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
                or target.username or target.password or target.port not in (None, 443)):
            raise ValueError("Unsupported Anubis release redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def release_open(url, timeout=30):
    return urllib.request.build_opener(ReleaseRedirect()).open(url, timeout=timeout)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def download(lock, target):
    # The lock is extension-owned, never supplied by a panel request. Restrict it
    # anyway so accidental edits cannot switch to mutable tags or plaintext URLs.
    version = lock["version"]
    expected = f"https://github.com/TecharoHQ/anubis/releases/download/v{version}/anubis-{version}-linux-amd64.tar.gz"
    if lock["url"] != expected:
        raise ValueError("Runtime URL must identify the pinned upstream GitHub release")
    if not re.fullmatch(r"[a-f0-9]{64}", lock["sha256"]):
        raise ValueError("Invalid runtime SHA-256")
    deadline = time.monotonic() + 180
    with release_open(expected, timeout=30) as source, Path(target).open("wb") as output:
        total = 0
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE or time.monotonic() > deadline:
                raise ValueError("Runtime archive exceeds the download limit")
            output.write(chunk)
    if digest(target) != lock["sha256"]:
        raise ValueError("Anubis archive SHA-256 mismatch; refusing to install it")


def extract_runtime(archive, destination, expected):
    archive, destination = Path(archive), Path(destination)
    if archive.stat().st_size > MAX_ARCHIVE or digest(archive) != expected:
        raise ValueError("Anubis archive SHA-256 mismatch; refusing to package or install it")
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        binary = [m for m in members if m.isfile() and PurePosixPath(m.name).parts[-2:] == ("bin", "anubis")]
        if len(binary) != 1:
            raise ValueError("Expected exactly one bin/anubis in the pinned archive")
        if sum(m.size for m in members) > MAX_EXPANDED or len(members) > 20000:
            raise ValueError("Runtime archive exceeds extraction limits")
        prefix = PurePosixPath(binary[0].name).parent.parent
        seen = set()
        for member in members:
            raw = PurePosixPath(member.name)
            if raw.is_absolute() or ".." in raw.parts or not (member.isdir() or member.isfile()):
                raise ValueError("Unsupported or unsafe runtime archive member")
            try:
                relative = raw.relative_to(prefix)
            except ValueError as exc:
                raise ValueError("Unexpected runtime archive layout") from exc
            if str(relative) == ".":
                continue
            if str(relative) in seen:
                raise ValueError("Duplicate runtime archive member")
            seen.add(str(relative))
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, target.open("xb") as out:
                    shutil.copyfileobj(source, out)
                target.chmod(0o755 if relative.parts == ("bin", "anubis") else 0o644)
    destination.chmod(0o755)
    # Archives may omit directory members; repair mkdir permissions filtered by
    # restrictive panel umasks so the unprivileged service can execute the cache.
    for directory in destination.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)


def manifest(directory, lock):
    directory = Path(directory)
    return {"version": lock["version"], "archive_sha256": lock["sha256"], "files": {
        p.relative_to(directory).as_posix(): digest(p)
        for p in sorted(directory.rglob("*")) if p.is_file() and p.name != ".manifest.json"}}


def verify(directory, record, lock):
    directory = Path(directory)
    if not isinstance(record, dict) or not isinstance(record.get("files"), dict) or len(record["files"]) > 20000:
        raise ValueError("Invalid runtime manifest")
    if record.get("version") != lock["version"] or record.get("archive_sha256") != lock["sha256"]:
        raise ValueError("Runtime manifest does not match the pinned release")
    if "bin/anubis" not in record.get("files", {}):
        raise ValueError("Runtime manifest has no Anubis binary")
    for relative, expected in record["files"].items():
        if not isinstance(relative, str) or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("Invalid runtime manifest checksum")
        raw = PurePosixPath(relative)
        if raw.is_absolute() or ".." in raw.parts:
            raise ValueError("Unsafe runtime manifest path")
        path = directory.joinpath(*raw.parts)
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError("Runtime payload checksum mismatch")


def acquire(cache, module, lock):
    """Download only on installation/update; immutable verified versions are reused."""
    cache, module = Path(cache), Path(module)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", lock["version"]):
        raise ValueError("Invalid pinned runtime version")
    cache.mkdir(mode=0o755, parents=True, exist_ok=True)
    target = cache / lock["version"]
    if target.exists():
        verify(target, json.loads((target / ".manifest.json").read_text()), lock)
        return target / "bin/anubis"
    with tempfile.TemporaryDirectory(prefix=".incoming-", dir=cache) as temporary:
        staging = Path(temporary) / "runtime"
        bundled = module / "runtime"
        record = json.loads((module / "runtime-manifest.json").read_text()) if bundled.exists() else None
        if record and record.get("version") == lock["version"] and record.get("archive_sha256") == lock["sha256"]:
            verify(bundled, record, lock)
            shutil.copytree(bundled, staging)
        else:
            archive = Path(temporary) / "anubis.tar.gz"
            download(lock, archive)
            extract_runtime(archive, staging, lock["sha256"])
            record = manifest(staging, lock)
        (staging / ".manifest.json").write_text(json.dumps(record, indent=2) + "\n")
        os.rename(staging, target)
    return target / "bin/anubis"
