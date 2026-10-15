#!/usr/bin/env python3
"""Build release assets and notes locally; publishing is handled by GitHub Actions."""
import argparse
from pathlib import Path
import re

from build import BASE, build
from metadata import version


def notes(release_version, changelog):
    match = re.search(r"^## " + re.escape(release_version) + r"(?:[ \t][^\n]*)?\n(.*?)(?=^## |\Z)",
                      changelog, re.MULTILINE | re.DOTALL)
    if not match or not match.group(1).strip():
        raise ValueError("Add a nonempty CHANGELOG.md section for " + release_version)
    return match.group(1).strip() + "\n"


def prepare(tag, output_dir=None):
    release_version = version(tag=tag)
    body = notes(release_version, (BASE / "CHANGELOG.md").read_text())
    out = Path(output_dir) if output_dir else BASE / "dist"
    out.mkdir(parents=True, exist_ok=True)
    assets = [build(output_dir=out), build(source_only=True, output_dir=out)]
    (out / "release-notes.md").write_text(body + "\n"
        "Install the standard ZIP through Plesk Extensions. The `-source.zip` is not installable. "
        "The installer downloads the exact Anubis version pinned by this extension and verifies its SHA-256. "
        "SHA-256 files are provided for both ZIPs.\n")
    return assets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Exact vMAJOR.MINOR.PATCH tag matching src/meta.xml")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        for asset in prepare(args.tag, args.output_dir):
            print(asset)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
