#!/bin/sh
# Usage: pem-distrust.sh FILE...
# Removes emSign ECC Root CA - G3 and AAA Certificate Services from PEM bundle files, in place.
# A certificate matches when its base64 body starts with the first 192 characters of one of the
# two roots. Other certificates and comment lines are kept. Needs only sh and awk.
for f in "$@"; do
  tmp=$(mktemp) || exit 2
  awk '
    BEGIN {
      bad["MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g"] = 1
      bad["MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj"] = 1
    }
    /^-----BEGIN CERTIFICATE-----/ { inblock = 1; block = $0 "\n"; body = ""; next }
    inblock {
      block = block $0 "\n"
      if ($0 ~ /^-----END CERTIFICATE-----/) {
        inblock = 0
        if (substr(body, 1, 192) in bad) removed++
        else printf "%s", block
      } else {
        line = $0; gsub(/[ \t\r]/, "", line); body = body line
      }
      next
    }
    { print }
    END { printf "%s: removed %d certificate(s)\n", FILENAME, removed + 0 > "/dev/stderr" }
  ' "$f" > "$tmp" && cat "$tmp" > "$f"
  rc=$?
  rm -f "$tmp"
  [ $rc -eq 0 ] || exit 2
done
