#!/bin/sh
# Build the SDK for Linux in a container and run every test there, then the
# end-to-end test once more with the device key in a PKCS#11 token.
#
#   ports/linux/tests/run-in-container.sh            (needs docker)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
image=koios-sdk-linux-test

docker build -q -t "$image" "$here" >/dev/null
docker run --rm -v "$root":/src:ro "$image" sh -euc '
    cmake -S /src -B /build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_FLAGS="-Werror" >/dev/null
    cmake --build /build -j"$(nproc)" >/build/build.log 2>&1 || { cat /build/build.log; exit 1; }
    grep -E "warning" /build/build.log || echo "built without warnings (-Werror)"
    ctest --test-dir /build --output-on-failure
    echo
    echo "== end to end again, the key in a PKCS#11 token =="
    python3 /src/ports/linux/tests/e2e.py --agent /build/ports/linux/koios-agent --scratch /build/e2e-pkcs11 --pkcs11
'
