#!/usr/bin/env bash
# Usage: emudhra_trust_check.sh IMAGE
# Exits 0 when no trust store in IMAGE trusts emSign ECC Root CA - G3 or
# AAA Certificate Services. Exits 1 when one does. Exits 2 when the check could
# not run, so a broken check never reads as a pass.
#
# It runs scripts/scan_image.py over the exported image filesystem. Some files keep
# both roots without trusting them, so hits at exactly these paths are ignored:
#   /etc/pki/ca-trust/source/blocklist/ (or blacklist/)       the blocklist itself
#   /usr/share/pki/ca-trust-source/                            vendor source, overridden by the blocklist
#   /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt    written as "Rejected Uses"
#   /usr/share/ca-certificates/                                Debian and Ubuntu source copies; the
#                                                              "!" entries keep them out of the bundle
# An unpatched image still fails, through the bundles that clients read.
set -u
image=${1:?usage: emudhra_trust_check.sh IMAGE}
scanner=$(dirname "$0")/../scripts/scan_image.py
out=$(mktemp) || exit 2
trap 'rm -f "$out"' EXIT

c=$(docker create "$image") || { echo "ERROR: cannot create a container from $image"; exit 2; }
docker export "$c" | python3 -I "$scanner" >"$out"
status=("${PIPESTATUS[@]}")
docker rm "$c" >/dev/null

if [ "${status[0]}" -ne 0 ] || [ "${status[1]}" -gt 1 ] || ! tail -n 1 "$out" | grep -Eq '^[0-9]+ hit\(s\)$'; then
  cat "$out"
  echo "ERROR: the trust-store scan of $image did not complete"
  exit 2
fi

hits=$(grep '^FOUND' "$out" | awk '$NF !~ /^\/etc\/pki\/ca-trust\/source\/(blocklist|blacklist)\/|^\/usr\/share\/pki\/ca-trust-source\/|^\/etc\/pki\/ca-trust\/extracted\/openssl\/ca-bundle\.trust\.crt$|^\/usr\/share\/ca-certificates\//')
if [ -n "$hits" ]; then
  printf '%s\n' "$hits"
  echo "FAIL: $image trusts a compromised eMudhra root"
  exit 1
fi
echo "PASS: $image"
