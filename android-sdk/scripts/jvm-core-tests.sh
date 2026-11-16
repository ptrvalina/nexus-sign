#!/usr/bin/env bash
# Compiles the platform-independent core of the Android SDK (signed payload
# parsing and display rules, mandate terms, device protocols, HKDF, errors,
# configuration) with the Kotlin compiler shipped inside a Gradle
# distribution, and runs its JVM unit tests against the shared vectors in
# auth-core/test-vectors. Needs no Android SDK and no network.
#
# This is not the Android build: KeyManager, BiometricPrompt, the Keystore and
# the network client are not compiled or run. The full build and tests are the
# CI job "android-sdk / build and unit tests" (./gradlew test).
#
#   GRADLE_LIB=/opt/gradle-8.14.3/lib android-sdk/scripts/jvm-core-tests.sh
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/.." && pwd)"
lib="${GRADLE_LIB:-$(dirname "$(readlink -f "$(command -v gradle)")")/../lib}"
jar() { ls "$lib"/$1 2>/dev/null | head -1 || true; }
stdlib=$(jar 'kotlin-stdlib-[0-9]*.jar'); compiler=$(jar 'kotlin-compiler-embeddable-*.jar'); junit=$(jar 'junit-4*.jar'); hamcrest=$(jar 'hamcrest-core-*.jar')
for f in "$stdlib" "$compiler" "$junit" "$hamcrest"; do [ -n "$f" ] || { echo "missing Kotlin compiler, stdlib or JUnit 4 in $lib" >&2; exit 2; }; done
cp="$compiler:$stdlib:$(jar 'kotlin-script-runtime-*.jar'):$(jar 'kotlin-reflect-*.jar'):$(jar 'kotlin-daemon-embeddable-*.jar'):$(jar 'annotations-*.jar'):$(jar 'trove4j-*.jar'):$(jar 'kotlinx-coroutines-core-jvm-*.jar')"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
main="$here/src/main/kotlin/com/nexis/nexussign"; tests="$here/src/test/kotlin/com/nexis/nexussign"
java -cp "$cp" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect -Werror -nowarn \
  -classpath "$stdlib:$junit:$hamcrest" -d "$out" \
  "$main/SignedTransaction.kt" "$main/MandateTerms.kt" "$main/DeviceProtocol.kt" "$main/Hkdf.kt" "$main/NEXUSSignError.kt" \
  "$main/NEXUSSignVersion.kt" "$main/NEXUSSignConfig.kt" \
  "$tests/TestJson.kt" "$tests/SignedTransactionTest.kt" "$tests/DeviceProtocolTest.kt" "$tests/BankTrustVectorsTest.kt" \
  "$tests/NEXUSSignConfigTest.kt" "$tests/MandateTermsVectorsTest.kt"
java -cp "$out:$repo/auth-core/test-vectors:$stdlib:$junit:$hamcrest" org.junit.runner.JUnitCore \
  com.nexis.nexussign.SignedTransactionTest com.nexis.nexussign.DeviceProtocolTest com.nexis.nexussign.BankTrustVectorsTest \
  com.nexis.nexussign.NEXUSSignConfigTest com.nexis.nexussign.MandateTermsVectorsTest
