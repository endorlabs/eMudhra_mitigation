#!/usr/bin/env python3
"""Scan a container image filesystem (tar on stdin, from `docker export`) for the
two roots that the compromised eMudhra intermediates chain to in public trust
stores. Matches PEM text and raw DER (Java cacerts, certs embedded in binaries)."""
import base64, sys, tarfile

ROOTS = {
    # SHA-256 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
    "emSign ECC Root CA - G3": "MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g",
    # SHA-256 D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
    "AAA Certificate Services": "MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj",
}
# Needles: first 64-char PEM line and the first 120 DER bytes
NEEDLES = []
for name, b64 in ROOTS.items():
    NEEDLES.append((name, "pem", b64[:64].encode()))
    NEEDLES.append((name, "der", base64.b64decode(b64[:160])))

hits = 0
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as tar:
    for m in tar:
        if not m.isfile() or m.size == 0 or m.size > 300 * 1024 * 1024:
            continue
        data = tar.extractfile(m).read()
        for name, kind, needle in NEEDLES:
            if needle in data:
                hits += 1
                print(f"FOUND  {name:26} {kind}  /{m.name}")
print(f"{hits} hit(s)")
sys.exit(1 if hits else 0)
