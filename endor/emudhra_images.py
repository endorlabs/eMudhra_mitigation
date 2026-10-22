#!/usr/bin/env python3
"""Write the eMudhra fix for each impacted container image.

Usage: emudhra_images.py IMAGES_JSON DEPS_JSON > emudhra_fixes.md
  IMAGES_JSON  endorctl api list -r PackageVersion output (container images)
  DEPS_JSON    endorctl api list -r DependencyMetadata output (must include meta.parent_uuid)

For each impacted image it prints the reason and three options:
  A  disable trust in the two affected roots (Dockerfile lines, rebuild)
  B  update to the vendor fix, or say that none exists (rebuild)
  C  replace the trust stores at runtime (docker run flags and Kubernetes YAML, no rebuild)
Exits 1 when at least one image is impacted. Uses the version rules of emudhra_classify.py.
"""
import importlib.util
import json
import os
import re
import sys

_spec = importlib.util.spec_from_file_location(
    "emudhra_classify", os.path.join(os.path.dirname(os.path.abspath(__file__)), "emudhra_classify.py"))
_classify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_classify)

FAMILY = {
    "debian": "deb", "ubuntu": "deb", "alpine": "alpine", "wolfi": "wolfi", "chainguard": "wolfi",
    "fedora": "fedora", "rhel": "rhel", "centos": "rhel", "rocky": "rhel", "almalinux": "rhel",
    "ol": "rhel", "amzn": "rhel", "sles": "suse", "opensuse-leap": "suse", "opensuse-tumbleweed": "suse",
}
SSL_CERTS_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
PKI_BUNDLE = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"

DEB_DISTRUST = """RUN sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \\
      /etc/ca-certificates.conf && update-ca-certificates"""
RHEL_BLOCKLIST = """RUN d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist; \\
    trust extract --overwrite --format=pem-bundle \\
      --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' $d/Comodo_AAA_Services_root.pem \\
 && trust extract --overwrite --format=pem-bundle \\
      --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' $d/emSign_ECC_Root_CA_-_G3.pem \\
 && update-ca-trust"""
COPY_PEM = "COPY pem-distrust.sh /tmp/"
APK_DISTRUST = f"RUN sh /tmp/pem-distrust.sh {SSL_CERTS_BUNDLE}"
CERTIFI_DISTRUST = "RUN find / -xdev -name cacert.pem -path '*certifi*' -exec sh /tmp/pem-distrust.sh {} +"
JAVA_DISTRUST = """COPY java-distrust.sh /tmp/
RUN sh /tmp/java-distrust.sh && rm /tmp/java-distrust.sh"""
OS_INSTALL = {
    "deb": "RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*",
    "alpine": "RUN apk add --no-cache ca-certificates-bundle",
}

DEB_UPDATE = "RUN apt-get update && apt-get install -y --only-upgrade ca-certificates && rm -rf /var/lib/apt/lists/*"
FEDORA_UPDATE = "RUN dnf -y upgrade ca-certificates"
PYPI_FLOOR = {"pypi://certifi": "certifi>=2026.10.19", "pypi://pip": "pip>=26.2.2", "pypi://uv": "uv>=0.13.4"}

K8S_VOLUMES = {
    "ssl-certs": """- name: emudhra-ssl-certs
  configMap:
    name: emudhra-etc-ssl-certs
    items:
    - {key: ca-certificates.crt, path: ca-certificates.crt}
    - {key: java-cacerts, path: java/cacerts}""",
    "pki": """- name: emudhra-pki
  projected:
    sources:
    - configMap:
        name: emudhra-pki-pem
        items:
        - {key: tls-ca-bundle.pem, path: pem/tls-ca-bundle.pem}
        - {key: email-ca-bundle.pem, path: pem/email-ca-bundle.pem}
        - {key: java-cacerts, path: java/cacerts}
    - configMap:
        name: emudhra-pki-objsign
        items: [{key: objsign-ca-bundle.pem, path: pem/objsign-ca-bundle.pem}]
    - configMap:
        name: emudhra-pki-openssl
        items: [{key: ca-bundle.trust.crt, path: openssl/ca-bundle.trust.crt}]""",
    "jdk": """- name: emudhra-jdk-cacerts
  configMap: {name: emudhra-jdk-cacerts}""",
}
MOUNTS = {
    "ssl-certs": ("clean/etc-ssl-certs", "/etc/ssl/certs", "emudhra-ssl-certs"),
    "pki": ("clean/pki-extracted", "/etc/pki/ca-trust/extracted", "emudhra-pki"),
    "jdk": ("clean/java", "/etc/emudhra/java", "emudhra-jdk-cacerts"),
}


def image_ref(name):
    """container://repo@sha256:x -> repo@sha256:x, container://repo@tag -> repo:tag."""
    ref = name.removeprefix("container://")
    repo, _, version = ref.rpartition("@")
    if not repo:
        return ref
    return ref if version.startswith("sha256:") else f"{repo}:{version}"


def is_os_ca(name):
    return name.endswith(("/ca-certificates", "/ca-certificates-bundle"))


def is_jdk(name):
    return re.fullmatch(r"sbom://[^/]+/(openjdk|jdk|jre|zulu|java|java_sdk|graalvm)", name) is not None


def is_go(name):
    return name in ("go://stdlib", "sbom://go")


def family_from_package(name):
    m = re.match(r"(debian|apk|rpm)://([^/]+)/", name)
    if not m:
        return None
    eco, ns = m.groups()
    if eco == "debian":
        return "deb"
    if eco == "apk":
        return "alpine" if ns == "alpine" else "wolfi"
    return "fedora" if ns == "fedora" else "rhel"


def os_bundle(family):
    return PKI_BUNDLE if family in ("rhel", "fedora") else SSL_CERTS_BUNDLE


def os_distrust(family):
    """Dockerfile lines that distrust the two roots in the OS trust store, or None."""
    if family == "deb":
        return [DEB_DISTRUST]
    if family in ("alpine", "wolfi"):
        return [COPY_PEM, APK_DISTRUST]
    if family in ("rhel", "fedora"):
        return [RHEL_BLOCKLIST]
    return None


def option_a(family, found, os_ca_present):
    """Option A: Dockerfile lines that disable trust in the two affected roots."""
    names = {n for n, _, _ in found}
    lines, notes = [], []

    def add(*new):
        for line in new:
            if line not in lines:
                lines.append(line)

    node = "sbom://node" in names
    if any(is_os_ca(n) for n in names) or (node and family and not os_ca_present):
        if node and not os_ca_present and family in OS_INSTALL:
            add(OS_INSTALL[family])
        distrust = os_distrust(family)
        if distrust:
            add(*distrust)
        else:
            notes.append("This image's operating system has no tested distrust step. Use the `trust extract` "
                         "steps on the incident page.")
        if family == "wolfi":
            notes.append("The `RUN` lines need a shell. Chainguard images without a shell need a `-dev` "
                         "variant or a build stage.")
    if any(is_jdk(n) for n in names):
        add(JAVA_DISTRUST)
    if names & {"pypi://certifi", "pypi://pip"}:
        add(COPY_PEM, CERTIFI_DISTRUST)
    if "pypi://uv" in names:
        add("ENV UV_NATIVE_TLS=1")
        notes.append("`UV_NATIVE_TLS=1` makes uv use the operating system trust store. Not tested.")
    if node:
        add("ENV NODE_OPTIONS=--use-openssl-ca", f"ENV SSL_CERT_FILE={os_bundle(family)}")
        notes.append("Node.js keeps its own copy of the roots. These two `ENV` lines make it use the operating "
                      "system trust store instead. If the image already sets `NODE_OPTIONS`, add the flag to it.")
    if any(is_go(n) for n in names):
        if family:
            notes.append("Go programs use the operating system trust store, so the lines above also cover them.")
        else:
            notes.append("Go programs use the trust store that the build copies into this image. Apply the "
                         "distrust lines in the build stage that provides it.")
    if any(n.startswith("cargo://") for n in names):
        notes.append("Rust programs that build in `webpki-roots` cannot have trust disabled after the build. "
                     "Use option B for them.")
    if COPY_PEM in lines:
        # The script holds the two certificates as match patterns. Remove it so that scans stay clean.
        add("RUN rm -f /tmp/pem-distrust.sh")
    if COPY_PEM in lines or JAVA_DISTRUST in lines:
        files = [f for f, used in (("pem-distrust.sh", COPY_PEM in lines),
                                   ("java-distrust.sh", JAVA_DISTRUST in lines)) if used]
        notes.append("Copy " + " and ".join(f"`scripts/{f}`" for f in files)
                     + " into the directory where you build the image.")
    return lines, notes


DISTRO_NAME = {
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine", "wolfi": "Wolfi", "chainguard": "Chainguard",
    "fedora": "Fedora", "rhel": "RHEL", "centos": "CentOS", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
    "ol": "Oracle Linux", "amzn": "Amazon Linux", "sles": "SLES", "opensuse-leap": "openSUSE Leap",
}

# Fixed ca-certificates per release, read from each distribution's package repository on 2026-10-21.
OS_FIXED = {
    ("debian", "12"): "20250419~deb12u2",
    ("debian", "13"): "20250419+deb13u1",
    ("ubuntu", "22.04"): "20260816ubuntu0.22.04.1",
    ("ubuntu", "24.04"): "20260816ubuntu0.24.04.1",
    ("ubuntu", "26.04"): "20260816ubuntu0.26.04.1",
    ("ubuntu", "26.10"): "20260816ubuntu0.26.10.1",
    **{("alpine", f"3.{minor}"): "20261020-r0" for minor in range(20, 25)},
    ("fedora", "44"): "2026.2.92_v9.0.319",
}
NO_FIX_DETAIL = {
    ("fedora", "43"): "The current Fedora 43 package, 2026.2.90_v9.0.317, still trusts the two affected roots.",
}
RHEL_LIKE = {"rhel", "centos", "rocky", "almalinux", "ol"}


def release_status(distro, version):
    """Return (state, fixed version, text) for the image's OS release.

    state is fixed, nofix, eol, or unknown. For fixed, text names the release. Otherwise it explains.
    """
    if distro in ("wolfi", "chainguard"):
        return "fixed", "20260909-r3", DISTRO_NAME[distro]
    if distro == "ubuntu":
        rel = version
    elif distro == "alpine":
        rel = ".".join(version.split(".")[:2])
    else:
        rel = version.split(".")[0]
    name = f"{DISTRO_NAME.get(distro, distro)} {rel}".strip()
    if (distro, rel) in OS_FIXED:
        return "fixed", OS_FIXED[(distro, rel)], name
    try:
        n = tuple(int(x) for x in rel.split("."))
    except ValueError:
        n = None
    if n and distro == "debian" and n < (12,):
        return "eol", None, f"{name} is end-of-life. Its security repository no longer serves ca-certificates."
    if n and distro == "ubuntu" and n < (22, 4):
        return "eol", None, f"{name} is out of standard support. The public Ubuntu archive has no fix."
    if n and distro == "ubuntu" and n < (26, 4):
        return "eol", None, f"{name} is an end-of-life interim release. It has no fix."
    if n and distro == "alpine" and n < (3, 20):
        return "eol", None, f"{name} is end-of-life. Its repository has no fix."
    if n and distro == "fedora" and n < (43,):
        return "eol", None, f"{name} is end-of-life. It has no fix."
    if n and distro in RHEL_LIKE and n <= (7,):
        return "eol", None, f"{name} is end-of-life. It has no fix."
    if distro == "amzn" and rel == "2":
        return "eol", None, "Amazon Linux 2 reached end of life on 2026-06-30. It has no fix."
    if (n and distro in {"fedora", "amzn"} | RHEL_LIKE) or distro.startswith(("sles", "opensuse")):
        return "nofix", None, " ".join(filter(None, [f"no vendor fix for {name} yet.", NO_FIX_DETAIL.get((distro, rel))]))
    return "unknown", None, name


def os_update_line(family, pkg):
    if family == "deb":
        return DEB_UPDATE
    if family == "alpine":
        return f"RUN apk upgrade --no-cache {pkg.rsplit('/', 1)[1]}"
    if family == "fedora":
        return FEDORA_UPDATE
    return None


def option_b(family, found, distro, version):
    """Option B: vendor updates for the image's release, and the trust stores that have no vendor fix."""
    lines, notes, none = [], [], []
    for n, v, c in found:
        if is_os_ca(n):
            state, fixed, text = release_status(distro, version)
            if state == "fixed":
                if family == "wolfi":
                    notes.append(f"Rebuild on the current {text} base image. It has `{fixed}` or later.")
                else:
                    lines.append(os_update_line(family, n))
                    notes.append(f"This installs `{fixed}`, the fixed version for {text}.")
            elif state == "nofix":
                none.append(f"`{n}` {v}: {text}")
            elif state == "eol":
                none.append(f"`{n}` {v}: {text} Plan to move to a supported release.")
            elif os_update_line(family, n):
                lines.append(os_update_line(family, n))
                notes.append(f"No fix information for {text or 'this release'}. After the upgrade, the check below "
                             "must print `PASS`. If it does not, use option A.")
            else:
                none.append(f"`{n}` {v}: no fix information for {text or 'this release'}.")
        elif is_jdk(n):
            none.append(f"`{n}` {v}: no JDK vendor fix yet.")
        elif n in PYPI_FLOOR:
            pass
        elif n == "sbom://node":
            major = _classify.nums(v)[:1]
            eol = f" Node.js {major[0]} is end-of-life." if major and (major[0] < 22 or major[0] % 2) else ""
            notes.append(f"Change `FROM` to Node.js 22.23.4, 24.22.1, 26.12.1, or later. This image has Node.js {v}.{eol}")
        elif is_go(n):
            ver = _classify.nums(v)
            eol = f" Go {ver[0]}.{ver[1]} no longer gets security fixes." if len(ver) > 1 and ver[:2] < (1, 26) else ""
            notes.append(f"Build the Go programs with Go 1.26.10, 1.27.3, or later, for example "
                         f"`FROM golang:1.27.3 AS build`. This image has {v}.{eol}")
        elif n.startswith("cargo://"):
            notes.append("Run `cargo update -p webpki-roots -p webpki-root-certs -p rustls-webpki`, then rebuild "
                         f"the Rust program. This image has {n.removeprefix('cargo://')} {v}.")
    pip = {PYPI_FLOOR[n] for n, _, _ in found if n in PYPI_FLOOR}
    if pip:
        # pip vendors its own certifi, so upgrade pip whenever Python trust stores are affected.
        pip = sorted(pip | {PYPI_FLOOR["pypi://pip"]})
        lines.append("RUN pip install --no-cache-dir --upgrade " + " ".join(f'"{p}"' for p in pip))
    return sorted(set(lines), key=lines.index), notes, none


def option_c(family, found, os_ca_present):
    """Option C: mounts and environment variables for a runtime fix, or the reason there is none."""
    names = {n for n, _, _ in found}
    blockers = []
    if any(n.startswith("cargo://") for n in names):
        blockers.append("Rust programs build in their roots and ignore runtime files")
    if family == "suse":
        blockers.append("the runtime fix was not tested on SUSE images")
    if blockers:
        return None, blockers

    os_affected = any(is_os_ca(n) for n in names)
    needs_bundle = any(n in PYPI_FLOOR or n == "sbom://node" or is_go(n) for n in names)
    mounts, env = [], []
    store = "pki" if family in ("rhel", "fedora") else "ssl-certs"
    bundle = os_bundle(family)
    if os_affected or (needs_bundle and not os_ca_present):
        mounts.append(store)
    if any(is_jdk(n) for n in names):
        mounts.append("jdk")
        env.append(("JAVA_TOOL_OPTIONS",
                    "-Djavax.net.ssl.trustStore=/etc/emudhra/java/cacerts -Djavax.net.ssl.trustStorePassword=changeit"))
    if names & set(PYPI_FLOOR):
        env += [("REQUESTS_CA_BUNDLE", bundle), ("PIP_CERT", bundle)]
    if "sbom://node" in names:
        env += [("NODE_OPTIONS", "--use-openssl-ca"), ("SSL_CERT_FILE", bundle)]
    return (mounts, env), []


CONFIGMAPS = {
    "ssl-certs": [
        ("emudhra-etc-ssl-certs", [
            "ca-certificates.crt="
            "clean/etc-ssl-certs/ca-certificates.crt",
            "java-cacerts=clean/etc-ssl-certs/java/cacerts"])],
    "pki": [
        ("emudhra-pki-pem", [
            "clean/pki-extracted/pem/tls-ca-bundle.pem",
            "clean/pki-extracted/pem/email-ca-bundle.pem",
            "java-cacerts=clean/pki-extracted/java/cacerts"]),
        ("emudhra-pki-objsign", [
            "clean/pki-extracted/pem/objsign-ca-bundle.pem"]),
        ("emudhra-pki-openssl", [
            "clean/pki-extracted/openssl/ca-bundle.trust.crt"])],
    "jdk": [
        ("emudhra-jdk-cacerts", ["cacerts=clean/java/cacerts"])],
}
KEYTOOL = ("keytool -importcert -noprompt -alias internal-ca"
           " -file internal-ca.pem -storepass changeit -keystore ")
PRIVATE_CA = {
    "ssl-certs": [
        "cat internal-ca.pem"
        " >> clean/etc-ssl-certs/ca-certificates.crt",
        KEYTOOL + "clean/etc-ssl-certs/java/cacerts"],
    "pki": [
        "cat internal-ca.pem"
        " >> clean/pki-extracted/pem/tls-ca-bundle.pem",
        KEYTOOL + "clean/pki-extracted/java/cacerts"],
    "jdk": [KEYTOOL + "clean/java/cacerts"],
}
PROBE = '-c "$(cat scripts/probe.sh)"'


def live_check(ref, flags=()):
    """The probe as a one-off container with the same flags, and in a pod."""
    docker = ["docker run --rm \\"] + [f"  {f} \\" for f in flags]
    docker.append(f"  --entrypoint sh {ref} {PROBE}")
    return [
        "Run this from the directory that holds `scripts/`. It starts a "
        "one-off container, so it works for images that exit right away:",
        "",
        "```sh", *docker, "```", "",
        "For a running Kubernetes pod:", "",
        "```sh", f"kubectl exec <pod-name> -- sh {PROBE}", "```", "",
        "The last line must say `RESULT: PASS`. `RESULT: FAIL` means the "
        "container still trusts the compromised eMudhra certificates. If "
        "it says `RESULT: CANNOT CHECK`, or the image has no shell, make "
        "an HTTPS request from the application to "
        "`https://dv-g3b-emudhra.we-have-a-problem.com/` instead. It "
        "must fail with a certificate error.",
    ]


def render_c(mounts, env, ref):
    out = [
        "Option C is a stopgap. It protects the container only while "
        "the deployment keeps these mounts and variables. The image "
        "itself stays impacted.",
        "",
    ]
    if mounts:
        out += [
            "1. Build the clean trust stores: copies of the trust "
            "stores with the two affected roots removed. Run this in "
            "the directory where you start containers. It needs Docker "
            "and Python 3. If you already built `clean/` for another "
            "image, skip this step.",
            "",
            "   ```sh",
            "   endor/make_clean_truststore.sh ./clean",
            "   ```",
            "",
            "   If the image trusts a private CA, for example a "
            "corporate proxy, also add it. The mount replaces the whole "
            "trust store, so a CA that the image build added would be "
            "lost:",
            "",
            "   ```sh",
        ]
        out += [f"   {c}" for m in mounts for c in PRIVATE_CA[m]]
        out += ["   ```", ""]
    n = 2 if mounts else 1
    out += [f"{n}. With Docker, start the container with these flags:",
            "", "   ```sh", "   docker run \\"]
    flags = [f'-v "$PWD/{MOUNTS[m][0]}:{MOUNTS[m][1]}:ro"' for m in mounts]
    flags += [f'-e {k}="{v}"' for k, v in env]
    out += [f"     {f} \\" for f in flags]
    out += [f"     {ref}", "   ```", ""]
    n += 1
    out += [f"{n}. With Kubernetes:", ""]
    if mounts:
        out += [
            "   Create the ConfigMaps in the namespace that runs the "
            "image. Run this from the directory that holds `clean/`. "
            "You can run it again safely.",
            "", "   ```sh", "   NS=<app-namespace>"]
        for m in mounts:
            for cm, files in CONFIGMAPS[m]:
                args = " ".join(f"--from-file={f}" for f in files)
                out.append(
                    f"   kubectl -n $NS create configmap {cm} {args}"
                    " --dry-run=client -o yaml"
                    " | kubectl -n $NS apply --server-side -f -")
        out += ["   ```", ""]
    out += ["   Add this to the container in the workload spec:", "",
            "   ```yaml"]
    if mounts:
        out.append("   volumeMounts:")
        for m in mounts:
            _, dst, vol = MOUNTS[m]
            out.append(f"   - {{name: {vol}, mountPath: {dst}, "
                       "readOnly: true}")
    if env:
        out.append("   env:")
        out += [f'   - {{name: {k}, value: "{v}"}}' for k, v in env]
    out += ["   ```", ""]
    if mounts:
        out += ["   Add this to the pod spec (`spec.template.spec` in a "
                "Deployment):", "", "   ```yaml", "   volumes:"]
        for m in mounts:
            out += ["   " + ln for ln in K8S_VOLUMES[m].splitlines()]
        out += ["   ```", ""]
    if any(k in ("JAVA_TOOL_OPTIONS", "NODE_OPTIONS") for k, _ in env):
        out += ["   If the deployment already sets `JAVA_TOOL_OPTIONS` "
                "or `NODE_OPTIONS`, add these values to it.", ""]
    n += 1
    out += [f"{n}. Check that the container no longer trusts the two "
            "affected roots:", ""]
    out += ["   " + ln if ln else "" for ln in live_check(ref, flags)]
    return out


def dockerfile_block(lines):
    return ["Add these lines to the Dockerfile of this image, after the `FROM` line. Then rebuild and redeploy "
            "the image.", "", "```dockerfile", *lines, "```", ""]


def section(img, found, family, os_ca_present, distro, version):
    name = img.get("meta", {}).get("name", "")
    ref = image_ref(name)
    cm = img.get("spec", {}).get("container_metadata", {})
    label = f"{DISTRO_NAME.get(distro, distro)} {version}".strip() or "no OS"
    names = {n for n, _, _ in found}
    s = [f"## `{ref}` ({label})", ""]
    s += [f"Namespace `{img.get('tenant_meta', {}).get('namespace', '')}`. Impacted because these trust stores "
          "still trust the two affected roots:", ""]
    os_state = release_status(distro, version)[0]
    for n, v, c in found:
        if is_os_ca(n) and os_state != "unknown":
            why = {"fixed": "a vendor fix exists for this release", "nofix": "no vendor fix for this release yet",
                   "eol": "no vendor fix, end-of-life release"}[os_state]
        else:
            why = "a vendor fix exists" if c == "upgrade" else "no vendor fix yet"
        s.append(f"- `{n}` {v} ({why})")

    check = f"Check the rebuilt image: `endor/emudhra_trust_check.sh {ref}` must print `PASS`."
    s += ["", "### Option A: disable trust in the two affected roots (rebuild)", ""]
    lines, notes = option_a(family, found, os_ca_present)
    if lines:
        s += dockerfile_block(lines)
    s += [f"- {n}" for n in notes] + ([""] if notes else [])
    if "sbom://node" in names:
        s += ["Check the rebuilt image. The trust-store check "
              "still reports the `node` program, because its own "
              "copy of the roots stays in the image unused.", ""]
        s += live_check("<rebuilt-image>") + [""]
    elif lines:
        s += [check, ""]

    s += ["### Option B: update to the vendor fix (rebuild)", ""]
    lines, notes, none = option_b(family, found, distro, version)
    if lines:
        s += dockerfile_block(lines)
    s += [f"- {n}" for n in notes] + ([""] if notes else [])
    if none:
        s += ["No vendor fix is available for:", ""] + [f"- {n}" for n in none] + [""]
        s += ["Use option A for these trust stores.", ""]
    if (lines or notes) and not none:
        s += [check, ""]

    s += ["### Option C: replace the trust stores at runtime (no rebuild)", ""]
    c, blockers = option_c(family, found, os_ca_present)
    if c:
        mounts, env = c
        s += render_c(mounts, env, ref)
    else:
        s.append(f"Not available for this image: {'; '.join(blockers)}. Use option A or B.")
    return ref, label, "\n".join(s), bool(c)


def main():
    with open(sys.argv[1]) as f:
        images = {o["uuid"]: o for o in json.load(f).get("list", {}).get("objects", [])}
    with open(sys.argv[2]) as f:
        deps = json.load(f).get("list", {}).get("objects", [])

    affected, os_ca_present = {}, set()
    for dm in deps:
        dep = dm.get("spec", {}).get("dependency_data", {})
        name, version = dep.get("package_name", ""), dep.get("resolved_version", "")
        parent = dm.get("meta", {}).get("parent_uuid", "")
        if parent not in images:
            continue
        if is_os_ca(name):
            os_ca_present.add(parent)
        cls = _classify.classify(dep.get("ecosystem", ""), name, version)
        if cls:
            affected.setdefault(parent, set()).add((name, version, cls))

    sections, summary = [], []
    for uuid in sorted(affected, key=lambda u: images[u].get("meta", {}).get("name", "")):
        img, found = images[uuid], sorted(affected[uuid])
        cm = img.get("spec", {}).get("container_metadata", {})
        distro, version = cm.get("distribution", ""), cm.get("version", "")
        family = FAMILY.get(distro) or next((family_from_package(n) for n, _, _ in found if is_os_ca(n)), None)
        ref, label, text, has_c = section(img, found, family, uuid in os_ca_present, distro, version)
        b_lines, b_notes, none = option_b(family, found, distro, version)
        b_state = "no" if none and not (b_lines or b_notes) else "partly" if none else "yes"
        summary.append(f"| `{ref}` | {label} | yes | {b_state} | {'yes' if has_c else 'no'} |")
        sections.append(text)

    print("# eMudhra CA compromise: fixes for impacted container images\n")
    print(f"{len(sections)} container image(s) still trust the two affected roots. Each has a section below. "
          "The guide `container_mitigation_per_image.md` explains how to apply the fixes.\n")
    if sections:
        print("| Image | OS | A: disable trust | B: vendor update | C: runtime replacement |\n|---|---|---|---|---|")
        print("\n".join(summary) + "\n")
        print("\n\n".join(sections))
    sys.exit(1 if sections else 0)


if __name__ == "__main__":
    main()
