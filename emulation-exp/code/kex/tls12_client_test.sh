#!/bin/bash
set -ex

ROOT="$(dirname $(pwd))"
CERT_DIR=${ROOT}/certs

# Use s_client from OpenSSL to connect to the server with TLS 1.2 and client certificate
openssl s_client \
    -connect localhost:4434 \
    -tls1_2 \
    --mutualAuth \
    -cert ${CERT_DIR}/client-cas_22KB.pem \
    -key ${CERT_DIR}/client-key.pem \
    -CAfile ${CERT_DIR}/CA.crt \
    -debug
