#!/usr/bin/env bash
# Usage: make_clean_truststore.sh OUT_DIR [JDK_IMAGE]
# Builds trust-store files that do not trust emSign ECC Root CA - G3 or
# AAA Certificate Services, ready to mount into containers at runtime:
#   OUT_DIR/etc-ssl-certs/   mount at /etc/ssl/certs (Debian, Ubuntu, Alpine). Holds
#                            ca-certificates.crt from Debian 12 with the fixed package,
#                            and java/cacerts for Debian and Ubuntu OS Java.
#   OUT_DIR/pki-extracted/   mount at /etc/pki/ca-trust/extracted (RHEL family, Amazon Linux).
#                            Built on UBI 9 with both roots blocklisted.
#   OUT_DIR/java/cacerts     mount over $JAVA_HOME/lib/security/cacerts of a JDK that ships its
#                            own store. Built from JDK_IMAGE (default eclipse-temurin:21-jre).
# Then it scans OUT_DIR and fails if either root is still trusted.
set -euo pipefail
out=${1:?usage: make_clean_truststore.sh OUT_DIR [JDK_IMAGE]}
mkdir -p "$out" && out=$(cd "$out" && pwd)
jdk=${2:-eclipse-temurin:21-jre}
here=$(cd "$(dirname "$0")/.." && pwd)
rm -rf "$out/etc-ssl-certs" "$out/pki-extracted" "$out/java"
mkdir -p "$out/etc-ssl-certs/java" "$out/java"

docker run --rm -v "$out:/out" debian:12 sh -c '
  apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates >/dev/null
  echo "Debian ca-certificates $(dpkg-query -W -f="\${Version}" ca-certificates)"
  cp /etc/ssl/certs/ca-certificates.crt /out/etc-ssl-certs/ca-certificates.crt'

docker run --rm -v "$out:/out" redhat/ubi9 sh -c '
  d=/etc/pki/ca-trust/source/blocklist
  trust extract --overwrite --format=pem-bundle \
    --filter="pkcs11:object=Comodo%20AAA%20Services%20root;type=cert" $d/Comodo_AAA_Services_root.pem
  trust extract --overwrite --format=pem-bundle \
    --filter="pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert" $d/emSign_ECC_Root_CA_-_G3.pem
  update-ca-trust
  cp -a /etc/pki/ca-trust/extracted /out/pki-extracted'

docker run --rm -v "$out:/out" -v "$here/scripts/java-distrust.sh:/java-distrust.sh:ro" "$jdk" sh -c '
  sh /java-distrust.sh
  cp "$JAVA_HOME/lib/security/cacerts" /out/java/cacerts'
cp "$out/java/cacerts" "$out/etc-ssl-certs/java/cacerts"

# pki-extracted keeps both roots in ca-bundle.trust.crt, marked as rejected. Skip that file.
tar -C "$out" -cf - --exclude pki-extracted/openssl/ca-bundle.trust.crt . | python3 -I "$here/scripts/scan_image.py"
