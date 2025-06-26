#!/bin/bash
set -ex

ROOT="$(dirname $(pwd))"
INSTALL_DIR=${ROOT}/install

OPENSSL=$(which openssl)

CERT_DIR=${ROOT}/certs
S2ND=${ROOT}/s2n-tls/build/bin/s2nd

##########################
# Setup network namespaces
##########################
${ROOT}/setup_ns.sh

function cleanup() {
    ##########################
    # Remove files
    ##########################
    rm -f s_timer.o

    ##########################
    # Remove network namespaces
    ##########################
    sudo ip netns del cli_ns
    sudo ip netns del srv_ns
}
trap cleanup INT KILL TERM EXIT


# TODO [childw]: dimensions over these options
#
#  --prefer-low-latency
#    Prefer low latency by clamping maximum outgoing record size at 1500.
#  --prefer-throughput
#    Prefer throughput by raising maximum outgoing record size to 16k
#  --enable-mfl
#    Accept client's TLS maximum fragment length extension request


##########################
# Start S2N Server

#Modify cert location as needed:
# 2KB certs
# --cert ${CERT_DIR}/server-cas_2KB.pem  \
# --key ${CERT_DIR}/server-key_2KB.pem \
# 18KB certs
# --cert ${CERT_DIR}/server-cas_18KB.pem  \
# --key ${CERT_DIR}/server-key_18KB.pem \
# 22KB certs
# --cert ${CERT_DIR}/server-cas_18KB.pem  \
# --key ${CERT_DIR}/server-key_18KB.pem \

##########################
sudo ip netns exec srv_ns ${S2ND} \
    --ciphers "test_mtls_s2n_ecdhe_rsa_with_aes_256_gcm_sha384" \
    --cert ${CERT_DIR}/ecdsa/server_rsa.crt \
    --key ${CERT_DIR}/ecdsa/server_rsa.key \
    --mutualAuth \
    --https-bench 0 \
    --no-session-ticket \
    --self-service-blinding \
    --corked-io \
    10.0.0.1 \
    4433 \
    1>/dev/null
