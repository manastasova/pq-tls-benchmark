#!/bin/bash
set -ex

ROOT="$(dirname $(pwd))"
INSTALL_DIR=${ROOT}/install

OPENSSL=$(which openssl)

CERT_DIR=${ROOT}/certs
CERT_DIR_MLDSA=/home/ubuntu/pq-tls-benchmark/emulation-exp/code/mldsa_certs
CERT_DIR=/home/ubuntu/pq-tls-benchmark/emulation-exp/code/certs

S2ND=${ROOT}/s2n-tls/bin/s2nd

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
##########################
sudo ip netns exec srv_ns ${S2ND} \
    --ciphers "20250512" \
    --cert ${CERT_DIR_MLDSA}/certificate_chain.pem \
    --key ${CERT_DIR_MLDSA}/leaf_key.pem \
    --https-bench 0 \
    --ca-file ${CERT_DIR_MLDSA}/root_ca_cert.pem \
    --prefer-throughput \
    --mutualAuth \
    --corked-io \
    --no-session-ticket \
    --self-service-blinding \
    10.0.0.1 \
    4433
