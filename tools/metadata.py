"""Portable metadata checks; Plesk's full schema is also checked on Plesk hosts."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

BASE = Path(__file__).resolve().parent.parent


def version(path=None, tag=None):
    root = ET.parse(path or BASE / "src/meta.xml").getroot()
    if root.tag != "module":
        raise ValueError("Extension metadata must have a module root")
    fields = {}
    for element in root:
        if element.tag in fields:
            raise ValueError("Duplicate metadata field: " + element.tag)
        fields[element.tag] = (element.text or "").strip()
    for name in ("id", "name", "description", "version", "release", "plesk_min_version", "os", "category"):
        if not fields.get(name):
            raise ValueError("Missing metadata field: " + name)
    if fields["id"] != "anubis-guard" or fields["os"] != "unix":
        raise ValueError("Unexpected extension ID or operating system")
    numeric = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    for name in ("version", "plesk_min_version"):
        if not re.fullmatch(numeric, fields[name]):
            raise ValueError("Invalid metadata version: " + name)
    if not re.fullmatch(r"[1-9][0-9]*", fields["release"]):
        raise ValueError("Metadata release must be a positive integer")
    if tag is not None and tag != "v" + fields["version"]:
        raise ValueError("Release tag must match metadata exactly: v" + fields["version"])
    return fields["version"]


if __name__ == "__main__":
    print("Extension metadata valid: " + version())
