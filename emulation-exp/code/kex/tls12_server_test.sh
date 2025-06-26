#!/bin/bash
set -ex

ROOT="$(dirname $(pwd))"
CERT_DIR=${ROOT}/certs
S2ND=${ROOT}/s2n-tls/build/bin/s2nd

# Start S2N Server with TLS 1.2 and mutual authentication
${S2ND} \
    --ciphers "test_all_tls12" \
    --cert ${CERT_DIR}/server-cas_22KB.pem \
    --key ${CERT_DIR}/server-key.pem \
    --https-bench 0 \
    --mutualAuth \
    --ca-file ${CERT_DIR}/CA.crt \
    --no-session-ticket \
    --self-service-blinding \
    0.0.0.0 \
    4434
