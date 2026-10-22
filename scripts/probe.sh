#!/bin/sh
# Usage inside a container: probe.sh
# Checks whether the container trusts the compromised eMudhra certificates. It connects with
# curl or wget to six test servers that the incident researchers run with those certificates.
# A fixed container refuses all six. First it connects to a normal HTTPS site, so that a missing
# client or a broken network never looks like a pass.
# Exits 0 on PASS, 1 on FAIL, 2 when the check cannot run.

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -sS -o /dev/null --max-time 15 "$1"
  else
    wget -q -O /dev/null -T 15 "$1"
  fi
}

row() {
  printf '  %-14s %-46s %s\n' "$1" "$2" "$3"
}

echo "eMudhra CA check: does this container trust the compromised eMudhra certificates?"
echo

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  echo "RESULT: CANNOT CHECK. The image has no curl or wget. Test from the application instead:"
  echo "an HTTPS request to https://dv-g3b-emudhra.we-have-a-problem.com/ must fail with a certificate error."
  exit 2
fi
if fetch https://www.debian.org/ 2>/dev/null; then
  row "Normal site" "www.debian.org" "connected  (OK: HTTPS works)"
else
  row "Normal site" "www.debian.org" "failed"
  echo
  echo "RESULT: CANNOT CHECK. A normal HTTPS site does not work either, so the result would mean nothing."
  echo "Check the container's network access and trust store."
  exit 2
fi

bad=0
n=0
for h in dv-g3b ov-g3c ev-g3b dv-g3b-aaa ov-g3c-aaa ev-g3b-aaa; do
  n=$((n + 1))
  host="$h-emudhra.we-have-a-problem.com"
  if fetch "https://$host/" 2>/dev/null; then
    row "Test server $n" "$host" "connected  (BAD: trusts a compromised certificate)"
    bad=$((bad + 1))
  else
    row "Test server $n" "$host" "refused    (good)"
  fi
done

echo
if [ "$bad" -eq 0 ]; then
  echo "RESULT: PASS. This container does not trust the compromised eMudhra certificates."
  exit 0
fi
echo "RESULT: FAIL. This container trusts the compromised eMudhra certificates ($bad of 6 test servers"
echo "connected). Apply a fix from this image's section in emudhra_fixes.md."
exit 1
