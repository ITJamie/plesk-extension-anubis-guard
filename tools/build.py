#!/usr/bin/python3
"""Build a deterministic installer ZIP; optionally bundle the verified runtime."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import zipfile

BASE = Path(__file__).resolve().parent.parent
from metadata import version

VERSION = version()
sys.path.insert(0, str(BASE / "src/sbin"))
from ag_payload import digest, download as download_runtime, extract_runtime, manifest


def zip_tree(root, output):
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            name = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            executable = bool(path.stat().st_mode & stat.S_IXUSR)
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            archive.writestr(info, path.read_bytes())
    output.with_suffix(output.suffix + ".sha256").write_text(digest(output) + "  " + output.name + "\n")


def build(runtime_archive=None, download=False, source_only=False, output_dir=None):
    out = Path(output_dir) if output_dir else BASE / "dist"
    out.mkdir(parents=True, exist_ok=True)
    lock = json.loads((BASE / "runtime.lock.json").read_text())
    with tempfile.TemporaryDirectory(prefix="anubis-build-") as directory:
        temporary = Path(directory)
        staging = temporary / "package"
        if source_only:
            shutil.copytree(BASE, staging, ignore=shutil.ignore_patterns("dist", "__pycache__", "*.pyc", ".git", ".cache"))
            # htdocs/dist contains the bundled panel assets, not build artifacts.
            shutil.copytree(BASE / "src/htdocs/dist", staging / "src/htdocs/dist")
            output = out / f"anubis-guard-{VERSION}-source.zip"
        else:
            if download:
                runtime_archive = temporary / "anubis.tar.gz"
                download_runtime(lock, runtime_archive)
            shutil.copytree(BASE / "src", staging, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            if runtime_archive:
                runtime = staging / "sbin/runtime"
                extract_runtime(Path(runtime_archive), runtime, lock["sha256"])
                (staging / "sbin/runtime-manifest.json").write_text(json.dumps(manifest(runtime, lock), indent=2) + "\n")
            shutil.copy2(BASE / "runtime.lock.json", staging / "sbin/runtime.lock.json")
            for name in ("LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "CHANGELOG.md", "runtime.lock.json"):
                shutil.copy2(BASE / name, staging / name)
            shutil.copytree(BASE / "docs", staging / "docs")
            suffix = "-offline" if runtime_archive else ""
            output = out / f"anubis-guard-{VERSION}{suffix}.zip"
        zip_tree(staging, output)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-archive", type=Path)
    parser.add_argument("--download-runtime", action="store_true")
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.source_only and (args.runtime_archive or args.download_runtime):
        parser.error("Source-only mode does not accept a runtime")
    if args.runtime_archive and args.download_runtime:
        parser.error("Choose an existing archive or a download")
    try:
        print(build(args.runtime_archive, args.download_runtime, args.source_only, args.output_dir))
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
