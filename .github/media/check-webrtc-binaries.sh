#!/usr/bin/env bash
# Evidence for the pinned WebRTC binaries (finding D-14, THIRD_PARTY_MEDIA.md
# TPM-2 and TPM-3): downloads exactly the pinned versions, records their
# SHA-256, checks the checksums the publishers state and the Maven Central
# PGP signature, and lists the licence files inside each artifact. It fails
# on a mismatch or an invalid signature. It does not decide whether the
# publisher is trustworthy: the key fingerprint and the licence files are
# printed for the owner's review.
set -euo pipefail

ANDROID_VERSION="$(sed -n 's/.*io\.github\.webrtc-sdk:android:\([^"]*\)".*/\1/p' android-sdk-calls/build.gradle.kts)"
IOS_VERSION="$(sed -n 's/.*stasel\/WebRTC\.git", exact: "\([^"]*\)".*/\1/p' ios-sdk-calls/Package.swift)"
[ -n "$ANDROID_VERSION" ] && [ -n "$IOS_VERSION" ] || { echo "could not read the pinned versions"; exit 1; }
OUT="${1:-webrtc-binaries}"
mkdir -p "$OUT"
cd "$OUT"
report() { echo "$1" | tee -a report.txt; }

# ----- Android: io.github.webrtc-sdk:android from Maven Central -----
BASE="https://repo1.maven.org/maven2/io/github/webrtc-sdk/android/$ANDROID_VERSION/android-$ANDROID_VERSION"
for ext in aar aar.asc aar.sha1 aar.md5 pom pom.asc; do curl -fsSL --retry 3 -o "android.$ext" "$BASE.$ext"; done
curl -fsSL --retry 3 -o android.aar.sha256 "$BASE.aar.sha256" 2>/dev/null || rm -f android.aar.sha256
report "Android io.github.webrtc-sdk:android:$ANDROID_VERSION"
report "  SHA-256 (computed): $(sha256sum android.aar | cut -d' ' -f1)"
[ "$(sha1sum android.aar | cut -d' ' -f1)" = "$(tr -d ' \n' < android.aar.sha1 | cut -c1-40)" ] || { report "  SHA-1 MISMATCH with Maven Central"; exit 1; }
report "  SHA-1 matches Maven Central's .sha1"
if [ -f android.aar.sha256 ]; then
  [ "$(sha256sum android.aar | cut -d' ' -f1)" = "$(tr -d ' \n' < android.aar.sha256 | cut -c1-64)" ] || { report "  SHA-256 MISMATCH with Maven Central"; exit 1; }
  report "  SHA-256 matches Maven Central's .sha256"
fi
export GNUPGHOME="$PWD/gnupg"; mkdir -p -m 700 "$GNUPGHOME"
KEYID="$(gpg --list-packets android.aar.asc 2>/dev/null | sed -n 's/.*keyid \([0-9A-F]*\).*/\1/p' | head -1)"
[ -n "$KEYID" ] || { report "  no signature key ID in the .asc"; exit 1; }
gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$KEYID" >/dev/null 2>&1 \
  || gpg --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys "$KEYID" >/dev/null 2>&1 \
  || { report "  signing key $KEYID not found on the key servers"; exit 1; }
gpg --batch --verify android.aar.asc android.aar 2>verify.txt || { cat verify.txt; report "  PGP signature INVALID"; exit 1; }
gpg --batch --verify android.pom.asc android.pom 2>>verify.txt || { cat verify.txt; report "  POM signature INVALID"; exit 1; }
report "  PGP signature valid (AAR and POM), key $(gpg --batch --with-colons --fingerprint "$KEYID" | awk -F: '/^fpr/{print $10; exit}')"
report "  key user IDs: $(gpg --batch --with-colons --list-keys "$KEYID" | awk -F: '/^uid/{printf "%s; ", $10}')"
report "  licence files in the AAR: $(unzip -l android.aar | awk '{print $4}' | grep -iE 'licen|notice|copying' | tr '\n' ' ' || true)"
report "  POM licence: $(sed -n 's:.*<name>\(.*\)</name>.*:\1:p' android.pom | tail -n +2 | head -3 | tr '\n' ';')"

# ----- iOS: stasel/WebRTC binaryTarget -----
curl -fsSL --retry 3 -o ios-Package.swift "https://raw.githubusercontent.com/stasel/WebRTC/$IOS_VERSION/Package.swift"
URL="$(sed -n 's/.*url: *"\([^"]*\)".*/\1/p' ios-Package.swift | head -1)"
SUM="$(sed -n 's/.*checksum: *"\([0-9a-f]*\)".*/\1/p' ios-Package.swift | head -1)"
[ -n "$URL" ] && [ -n "$SUM" ] || { report "iOS: no binaryTarget url or checksum in Package.swift of $IOS_VERSION"; exit 1; }
curl -fsSL --retry 3 -o ios.zip "$URL"
report "iOS stasel/WebRTC $IOS_VERSION"
report "  binaryTarget: $URL"
report "  SHA-256 (computed): $(sha256sum ios.zip | cut -d' ' -f1)"
[ "$(sha256sum ios.zip | cut -d' ' -f1)" = "$SUM" ] || { report "  CHECKSUM MISMATCH with the tag's Package.swift ($SUM)"; exit 1; }
report "  matches the checksum in Package.swift of tag $IOS_VERSION"
report "  licence files in the XCFramework: $(unzip -l ios.zip | awk '{print $4}' | grep -iE 'licen|notice|copying' | tr '\n' ' ' || true)"
