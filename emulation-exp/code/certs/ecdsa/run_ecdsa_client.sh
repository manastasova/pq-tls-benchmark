#!/bin/bash
set -ex

ROOT="$(dirname $(dirname $(pwd)))"
INSTALL_DIR=${ROOT}/install

CERT_DIR=${ROOT}/certs/ecdsa
S2NC=${ROOT}/s2n-tls/build/bin/s2nc

# Start S2N Client with P256 ECDSA certificate
sudo ip netns exec cli_ns ${S2NC} \
    --ciphers "test_all_ecdsa" \
    --cert ${CERT_DIR}/client_p256.pem \
    --key ${CERT_DIR}/client_p256.key \
    --https-bench 0 \
    --ca-file ${CERT_DIR}/ca_p256.crt \
    --no-session-ticket \
    --self-service-blinding \
    --corked-io \
    10.0.0.1 \
    4433
