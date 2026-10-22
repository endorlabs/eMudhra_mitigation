#!/usr/bin/env python3
"""Classify container dependencies from `endorctl api list -r DependencyMetadata` output.

Reads the JSON on stdin and prints one tab-separated row per affected dependency:
class, namespace, image, package, version. Same rules as emudhra_policy.rego.

  upgrade  a fixed version exists and this one is older
  verify   no vendor fix exists yet; apply the manual distrust and verify the image

Exits 1 when it prints at least one row. Fixed versions as of 2026-10-21.
"""
import json
import re
import sys

DEBIAN_FIXED = {
    "20250419~deb12u2",
    "20250419+deb13u1",
    "20260816+nmu1",
    "20260816ubuntu0.22.04.1",
    "20260816ubuntu0.24.04.1",
    "20260816ubuntu0.26.04.1",
    "20260816ubuntu0.26.10.1",
}
DEBIAN_LAST_UNFIXED_DATE = (20260816,)
DEBIAN_FIRST_FIXED_LINE = (20230311,)  # Debian 11 and older ship older versions
UBUNTU_LEGACY = re.compile(r"(~|ubuntu0\.)(1[0-9]|20|21|23|25)\.(04|10)")  # Ubuntu 20.04 and older, EOL interim releases
DEBIAN_LEGACY_BACKPORT = re.compile(r"deb(9|10|11)u")  # Debian 11 and older backports
ALPINE_FIXED_FROM = (20261020,)
WOLFI_FIXED_DATE, WOLFI_FIXED_RELEASE = (20260909,), 3
FEDORA_FIXED_FROM = (2026, 2, 92)
FIXED_FROM = {
    "pypi://certifi": (2026, 10, 19),
    "pypi://pip": (26, 2, 2),
    "pypi://uv": (0, 13, 4),
    "cargo://webpki-roots": (1, 0, 10),
    "cargo://webpki-root-certs": (1, 0, 10),
    "cargo://rustls-webpki": (0, 103, 16),
}
NODE_FIXED_FROM = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
GO_FIXED_FROM = {26: (1, 26, 10), 27: (1, 27, 3)}


def nums(v):
    """Leading dotted number of a version, without an RPM epoch."""
    m = re.search(r"[0-9]+(\.[0-9]+)*", v.split(":", 1)[-1])
    return tuple(int(x) for x in m.group(0).split(".")) if m else ()


def wolfi_fixed(v):
    if nums(v) > WOLFI_FIXED_DATE:
        return True
    m = re.search(r"-r([0-9]+)$", v)
    return nums(v) == WOLFI_FIXED_DATE and m is not None and int(m.group(1)) >= WOLFI_FIXED_RELEASE


def node_fixed(n):
    return bool(n) and (n[0] >= 27 or (n[0] in NODE_FIXED_FROM and n >= NODE_FIXED_FROM[n[0]]))


def go_fixed(n):
    return n >= (1, 28) or (len(n) > 1 and n[1] in GO_FIXED_FROM and n >= GO_FIXED_FROM[n[1]])


def classify(eco, name, v):
    ca = re.search(r"/ca-certificates(-bundle)?$", name) is not None
    if eco == "ECOSYSTEM_DEBIAN" and name.endswith("/ca-certificates"):
        if v not in DEBIAN_FIXED and nums(v) <= DEBIAN_LAST_UNFIXED_DATE:
            legacy = nums(v) < DEBIAN_FIRST_FIXED_LINE or UBUNTU_LEGACY.search(v) or DEBIAN_LEGACY_BACKPORT.search(v)
            return "verify" if legacy else "upgrade"
    elif eco == "ECOSYSTEM_APK" and ca and name.startswith("apk://alpine/"):
        if nums(v) < ALPINE_FIXED_FROM:
            return "upgrade"
    elif eco == "ECOSYSTEM_APK" and ca and re.match(r"apk://(wolfi|chainguard)/", name):
        if not wolfi_fixed(v):
            return "upgrade"
    elif eco == "ECOSYSTEM_RPM" and name == "rpm://fedora/ca-certificates":
        if nums(v) < FEDORA_FIXED_FROM:
            return "upgrade"
    elif eco == "ECOSYSTEM_RPM" and name.endswith("/ca-certificates"):
        return "verify"
    elif name in FIXED_FROM:
        if nums(v) < FIXED_FROM[name]:
            return "upgrade"
    elif name == "sbom://node":
        if not node_fixed(nums(v)):
            return "upgrade"
    elif name in ("go://stdlib", "sbom://go"):
        if not go_fixed(nums(v)):
            return "upgrade"
    elif re.fullmatch(r"sbom://[^/]+/(openjdk|jdk|jre|zulu|java|java_sdk|graalvm)", name):
        return "verify"
    return None


def main():
    objects = json.load(sys.stdin).get("list", {}).get("objects", [])
    rows = set()
    for dm in objects:
        imp = dm.get("spec", {}).get("importer_data", {})
        dep = dm.get("spec", {}).get("dependency_data", {})
        if not imp.get("package_name", "").startswith("container://"):
            continue
        name, version = dep.get("package_name", ""), dep.get("resolved_version", "")
        cls = classify(dep.get("ecosystem", ""), name, version)
        if cls:
            image = imp.get("package_version_name") or imp.get("package_name")
            rows.add((cls, dm.get("tenant_meta", {}).get("namespace", ""), image, name, version))
    for row in sorted(rows):
        print("\t".join(row))
    sys.exit(1 if rows else 0)


if __name__ == "__main__":
    main()
