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

# new_certs/server_rsa4096_cert.pem
# new_certs/server_rsa4096_key.pem
# new_certs/ca_rsa4096_cert.pem

# server-cas.pem
# server-key.pem
# CA.crt

# --cert ${CERT_DIR}/new_certs/server_rsa4096_cert.pem \
# --key ${CERT_DIR}/new_certs/server_rsa4096_key.pem \
# --mutualAuth \
# --ca-file ${CERT_DIR}/new_certs/ca_rsa4096_cert.pem \

# --cert ${CERT_DIR}/server-cas.pem \
# --key ${CERT_DIR}/server-key.pem \
# --mutualAuth \
# --ca-file ${CERT_DIR}/CA.crt \
##########################
sudo ip netns exec srv_ns ${S2ND} \
    --ciphers "PQ-TLS-1-3-2023-06-01" \
    --cert ${CERT_DIR}/new_certs/server_rsa4096_cert.pem  \
    --key ${CERT_DIR}/new_certs/server_rsa4096_key.pem \
    --https-bench 0 \
    --mutualAuth \
    --ca-file ${CERT_DIR}/new_certs/ca_rsa4096_cert.pem\
    --no-session-ticket \
    --self-service-blinding \
    --corked-io \
    10.0.0.1 \
    4433 \
    1>/dev/null
