# The Linux build and test environment of the SDK's Linux port: Debian with
# OpenSSL 3, libcurl, cJSON, and a software PKCS#11 token (SoftHSM) behind
# OpenSSL's pkcs11 provider, which stands in for a key held in OP-TEE or a
# secure element.
#
#   ports/linux/tests/run-in-container.sh
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config python3 ca-certificates \
        libssl-dev libcurl4-openssl-dev libcjson-dev openssl \
        softhsm2 pkcs11-provider \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
