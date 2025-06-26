#!/bin/bash
set -ex

ROOT="$(dirname $(dirname $(pwd)))"
INSTALL_DIR=${ROOT}/install

CERT_DIR=${ROOT}/certs/ecdsa
S2ND=${ROOT}/s2n-tls/build/bin/s2nd

# Start S2N Server with P256 ECDSA certificate
sudo ip netns exec srv_ns ${S2ND} \
    --ciphers "test_all_ecdsa" \
    --cert ${CERT_DIR}/server_p256.pem \
    --key ${CERT_DIR}/server_p256.key \
    --https-bench 0 \
    --mutualAuth \
    --ca-file ${CERT_DIR}/ca_p256.crt \
    --no-session-ticket \
    --self-service-blinding \
    --corked-io \
    10.0.0.1 \
    4433
