# Remove emSign ECC Root CA - G3 and AAA Certificate Services from the JDK cacerts, matched by SHA-256
for fp in 86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B \
          D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4; do
  keytool -list -cacerts -storepass changeit 2>/dev/null |
    awk -v fp="$fp" '/trustedCertEntry/{a=$0; sub(/, [A-Z][a-z][a-z] [0-9]+, [0-9]+, trustedCertEntry,.*$/, "", a)} index($0, fp){print a}' |
    while IFS= read -r alias; do
      keytool -delete -cacerts -storepass changeit -alias "$alias" && echo "removed: $alias"
    done
done
