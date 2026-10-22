# eMudhra CA compromise: fix each impacted container image

Status as of 2026-10-21.

## Scope

An image is impacted when any trust store in it, from the operating system or from a runtime such
as Java, Python, or Node.js, still trusts one of **the two affected roots**:

| Root | SHA-256 |
|---|---|
| emSign ECC Root CA - G3 | `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` |
| AAA Certificate Services | `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4` |

## What you get

The script `endor/emudhra_fixes.sh` reads your container scan results from Endor Labs. It finds
every scanned image that still trusts the two affected roots, and it writes a report,
`emudhra_fixes.md`, with one section for each of those images. Each section has:

- **Why the image is impacted:** the trust stores in the image, with their versions.
- **Option A, disable trust (rebuild):** the exact Dockerfile lines that remove trust in the two
  affected roots from every trust store in the image. It works whether or not a vendor fix exists.
- **Option B, vendor update (rebuild):** the vendor fix for the image's operating system release
  and runtimes. It names the fixed package version for that release, for example `20250419~deb12u2`
  for Debian 12. If the release has no vendor fix, the section says so, and it says when the release
  is end-of-life and will not get one.
- **Option C, runtime replacement (no rebuild):** numbered steps that build clean trust stores and mount
  them into the running container, with Docker or Kubernetes. The report offers option C only for
  images where it works. For example, Rust programs build their trust store into the program
  itself, so they get no option C.

This is one section of a real report:

> ## `emudhra-test-deb-old:latest` (Debian 12)
>
> Namespace `acme`. Impacted because these trust stores still trust the two affected roots:
>
> - `debian://debian/ca-certificates` 20230311+deb12u1 (a vendor fix exists for this release)
>
> ### Option A: disable trust in the two affected roots (rebuild)
>
> Add these lines to the Dockerfile of this image, after the `FROM` line. Then rebuild and redeploy the image.
>
> ```dockerfile
> RUN sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
>       /etc/ca-certificates.conf && update-ca-certificates
> ```
>
> Check the rebuilt image: `endor/emudhra_trust_check.sh emudhra-test-deb-old:latest` must print `PASS`.
>
> ### Option B: update to the vendor fix (rebuild)
>
> Add these lines to the Dockerfile of this image, after the `FROM` line. Then rebuild and redeploy the image.
>
> ```dockerfile
> RUN apt-get update && apt-get install -y --only-upgrade ca-certificates && rm -rf /var/lib/apt/lists/*
> ```
>
> - This installs `20250419~deb12u2`, the fixed version for Debian 12.
>
> Check the rebuilt image: `endor/emudhra_trust_check.sh emudhra-test-deb-old:latest` must print `PASS`.
>
> ### Option C: replace the trust stores at runtime (no rebuild)
>
> Option C is a stopgap. It protects the container only while the deployment keeps these mounts and variables. The image itself stays impacted.
>
> 1. Build the clean trust stores: copies of the trust stores with the two affected roots removed. Run this in the directory where you start containers. It needs Docker and Python 3. If you already built `clean/` for another image, skip this step.
>
>    ```sh
>    endor/make_clean_truststore.sh ./clean
>    ```
>
>    If the image trusts a private CA, for example a corporate proxy, also add it. The mount replaces the whole trust store, so a CA that the image build added would be lost:
>
>    ```sh
>    cat internal-ca.pem >> clean/etc-ssl-certs/ca-certificates.crt
>    keytool -importcert -noprompt -alias internal-ca -file internal-ca.pem -storepass changeit -keystore clean/etc-ssl-certs/java/cacerts
>    ```
>
> 2. With Docker, start the container with these flags:
>
>    ```sh
>    docker run \
>      -v "$PWD/clean/etc-ssl-certs:/etc/ssl/certs:ro" \
>      emudhra-test-deb-old:latest
>    ```
>
> 3. With Kubernetes:
>
>    Create the ConfigMaps in the namespace that runs the image. Run this from the directory that holds `clean/`. You can run it again safely.
>
>    ```sh
>    NS=<app-namespace>
>    kubectl -n $NS create configmap emudhra-etc-ssl-certs --from-file=ca-certificates.crt=clean/etc-ssl-certs/ca-certificates.crt --from-file=java-cacerts=clean/etc-ssl-certs/java/cacerts --dry-run=client -o yaml | kubectl -n $NS apply --server-side -f -
>    ```
>
>    Add this to the container in the workload spec:
>
>    ```yaml
>    volumeMounts:
>    - {name: emudhra-ssl-certs, mountPath: /etc/ssl/certs, readOnly: true}
>    ```
>
>    Add this to the pod spec (`spec.template.spec` in a Deployment):
>
>    ```yaml
>    volumes:
>    - name: emudhra-ssl-certs
>      configMap:
>        name: emudhra-etc-ssl-certs
>        items:
>        - {key: ca-certificates.crt, path: ca-certificates.crt}
>        - {key: java-cacerts, path: java/cacerts}
>    ```
>
> 4. Check that the container no longer trusts the two affected roots:
>
>    Run this from the directory that holds `scripts/`. It starts a one-off container, so it works for images that exit right away:
>
>    ```sh
>    docker run --rm \
>      -v "$PWD/clean/etc-ssl-certs:/etc/ssl/certs:ro" \
>      --entrypoint sh emudhra-test-deb-old:latest -c "$(cat scripts/probe.sh)"
>    ```
>
>    For a running Kubernetes pod:
>
>    ```sh
>    kubectl exec <pod-name> -- sh -c "$(cat scripts/probe.sh)"
>    ```
>
>    The last line must say `RESULT: PASS`. `RESULT: FAIL` means the container still trusts the compromised eMudhra certificates. If it says `RESULT: CANNOT CHECK`, or the image has no shell, make an HTTPS request from the application to `https://dv-g3b-emudhra.we-have-a-problem.com/` instead. It must fail with a certificate error.

## Step 1. Make the report

```sh
endor/emudhra_fixes.sh
```

The script reads your existing container scans from Endor Labs, including child namespaces, and
writes `emudhra_fixes.md`. It does not start a scan and does not change anything. It needs
`endorctl`, already authenticated, and Python 3.

- By default it reads the namespace in `ENDOR_NAMESPACE`, like `endorctl`.
- `-n <namespace>` reads a different namespace.
- `-o <file>` writes the report to a different file.

The report starts with a table of all impacted images and the options that each one has. If an
image is not in the report, Endor Labs found no affected trust store in it.

## Step 2. Fix each image with option A, B, or C

### Option A or option B: rebuild

1. Find the image's section in the report.
2. Add the lines from the option to the Dockerfile that builds the image, after the `FROM` line. If
   you do not build the image yourself, for example a third-party image, create a new Dockerfile
   with the line `FROM <image>` followed by those lines. If the section says to copy a script from
   `scripts/`, copy it into the directory where you build the image.
3. Rebuild the image and redeploy it.
4. Do the check that the section names.

If option B says that a trust store has no vendor fix yet, use option A for that image.

### Option C: no rebuild

Follow the numbered steps in the image's option C section. They build the clean trust stores, then
give the `docker run` flags, the Kubernetes ConfigMap commands and YAML, and the check.

Option C is a stopgap. It protects the container only while the deployment keeps the mounted files
and environment variables. The image stays in the report, and you still need option A or B later.

## Step 3. Check the container

Each image's section has the exact check command for its option. The check runs
`scripts/probe.sh` in a one-off container, so it also works for images that exit right away, such
as base images:

```sh
docker run --rm --entrypoint sh <image> -c "$(cat scripts/probe.sh)"
```

For option C, the command also has the same `-v` and `-e` flags as the `docker run` in that
section. For a running Kubernetes pod, use `kubectl exec <pod-name> -- sh -c "$(cat scripts/probe.sh)"`.

The output explains itself, and the last line is the result. A fixed container prints:

```
eMudhra CA check: does this container trust the compromised eMudhra certificates?

  Normal site    www.debian.org                                 connected  (OK: HTTPS works)
  Test server 1  dv-g3b-emudhra.we-have-a-problem.com           refused    (good)
  ...
  Test server 6  ev-g3b-aaa-emudhra.we-have-a-problem.com       refused    (good)

RESULT: PASS. This container does not trust the compromised eMudhra certificates.
```

- `RESULT: FAIL` means that the container still trusts the compromised certificates. The lines that
  say `connected (BAD ...)` show which test servers it accepted.
- `RESULT: CANNOT CHECK` means that the image has no `curl` or `wget`, or no working HTTPS at all. Use
  the application's own runtime to make an HTTPS request to
  `https://dv-g3b-emudhra.we-have-a-problem.com/`. The request must fail with a certificate error.

After option A or B, scan the rebuilt image with Endor Labs
(`endorctl container scan --image <image>`), then run `endor/emudhra_fixes.sh` again. After option
B, the image is no longer in the report. After option A, the image stays in the report, because
Endor Labs reads package versions and option A does not change them. The check from the image's
section is the proof for option A.

## Vendor fixes that the report knows

Option B uses this table. Rows without a * were read from the distribution's package repository on
2026-10-21. Rows with a * come from the incident page and the vendors' published support dates.

| Release | Fixed `ca-certificates` | Status |
|---|---|---|
| Debian 12, 13 | `20250419~deb12u2`, `20250419+deb13u1` | |
| Debian 11 and older | none | end-of-life |
| Ubuntu 22.04, 24.04, 26.04, 26.10 | `20260816ubuntu0.<release>.1` | |
| Ubuntu 20.04 and older, 25.04, 25.10 | none | end-of-life or out of standard support |
| Alpine 3.20 to 3.24 | `20261020-r0` | |
| Alpine 3.19 and older | none | end-of-life |
| Wolfi, Chainguard * | `20260909-r3` | |
| Fedora 44 | `2026.2.92_v9.0.319` | |
| Fedora 43 | none yet. Its `2026.2.90_v9.0.317` still trusts the roots | |
| Fedora 42 and older | none | end-of-life |
| RHEL and UBI 8 to 10, Amazon Linux 2023 | none yet | |
| Rocky, Alma, Oracle Linux 8 to 10 * | none yet | |
| Amazon Linux 2 | none | end-of-life |
| CentOS 7, RHEL 7 * | none | end-of-life |

When a vendor ships a new fix, update `OS_FIXED` in `endor/emudhra_images.py`.

## Files

| File | Purpose |
|---|---|
| `endor/emudhra_fixes.sh` | Step 1: reads Endor Labs and writes the report |
| `endor/emudhra_images.py` | Writes the fixes for each image. `emudhra_fixes.sh` runs it |
| `endor/emudhra_classify.py` | The version rules that decide which images are impacted |
| `endor/make_clean_truststore.sh` | Builds the clean trust stores for option C |
| `endor/emudhra_trust_check.sh` | Checks that a rebuilt image no longer trusts the two affected roots |
| `scripts/pem-distrust.sh` | Removes the two affected roots from a certificate bundle file. Option A copies it into the build |
| `scripts/java-distrust.sh` | Removes the two affected roots from a Java trust store. Option A copies it into the build |
| `scripts/probe.sh` | Step 3: tries the incident test servers from inside a container. Uses `curl` or `wget` |
| `scripts/scan_image.py` | Finds the two affected roots in an image. The trust check and `make_clean_truststore.sh` use it |

