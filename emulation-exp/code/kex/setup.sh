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
    rm -f prime256v1.crt \
          s_timer.o

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
    --ciphers "PQ-TLS-1-3-2023-06-01" \
    --parallelize \
    --cert ${CERT_DIR}/server.crt \
    --key ${CERT_DIR}/server.key \
    --key-log s2n.keys \
    `# NOTE: 0 denotes "let client choose size by senging GET w/ qeury param giving # bytes` \
    --https-bench 0 \
    --corked-io \
    --no-session-ticket \
    --self-service-blinding \
    10.0.0.1 \
    4433 \
    1>/dev/null
