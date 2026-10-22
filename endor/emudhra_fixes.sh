#!/usr/bin/env bash
# Usage: emudhra_fixes.sh [-n NAMESPACE] [-o OUTPUT]
# Reads the container scans in the namespace and its child namespaces from Endor Labs, and writes
# the fix for each impacted image to OUTPUT (default emudhra_fixes.md). It reads data only.
# Without -n, endorctl uses its default namespace, from ENDOR_NAMESPACE.
# Needs endorctl, already authenticated, and Python 3.
set -euo pipefail
nsflag=()
out=emudhra_fixes.md
while getopts "n:o:" opt; do
  case $opt in
    n) nsflag=(-n "$OPTARG") ;;
    o) out=$OPTARG ;;
    *) echo "usage: emudhra_fixes.sh [-n NAMESPACE] [-o OUTPUT]" >&2; exit 2 ;;
  esac
done
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Reading container images from Endor Labs namespace ${nsflag[1]:-${ENDOR_NAMESPACE:-(endorctl default)}} ..." >&2
endorctl api list -r PackageVersion ${nsflag[@]+"${nsflag[@]}"} --traverse --list-all -t 10m \
  --filter "spec.ecosystem==ECOSYSTEM_CONTAINER and context.type in [CONTEXT_TYPE_MAIN, CONTEXT_TYPE_REF]" \
  --field-mask "uuid,tenant_meta.namespace,meta.name,spec.container_metadata.distribution,spec.container_metadata.version" \
  > "$tmp/images.json"

echo "Reading trust-store packages in those images ..." >&2
endorctl api list -r DependencyMetadata ${nsflag[@]+"${nsflag[@]}"} --traverse --list-all -t 10m \
  --filter "spec.importer_data.package_name matches '^container://' and context.type in [CONTEXT_TYPE_MAIN, CONTEXT_TYPE_REF] and spec.dependency_data.package_name matches 'ca-certificates|certifi$|pip$|uv$|stdlib$|^sbom://|webpki'" \
  --field-mask "meta.parent_uuid,spec.dependency_data.package_name,spec.dependency_data.resolved_version,spec.dependency_data.ecosystem" \
  > "$tmp/deps.json"

rc=0
python3 -I "$here/emudhra_images.py" "$tmp/images.json" "$tmp/deps.json" > "$out" || rc=$?
case $rc in
  0) echo "No impacted images found. Report: $out" >&2 ;;
  1) echo "$(grep -c '^## `' "$out") impacted image(s). Report written to $out" >&2 ;;
  *) echo "ERROR: could not build the report" >&2; exit 2 ;;
esac
