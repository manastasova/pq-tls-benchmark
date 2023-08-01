#!/bin/bash
set -ex

ROOT="$(dirname $(pwd))"
INSTALL_DIR=${ROOT}/install

OPENSSL=$(which openssl)

CERT_DIR=${ROOT}/certs
mkdir -p ${CERT_DIR}
S2ND=${ROOT}/s2n-tls/build/bin/s2nd

##########################
# Setup network namespaces
##########################
${ROOT}/setup_ns.sh

##########################
# Generate ECDSA P-256 cert
##########################
# generate curve parameters
${OPENSSL} ecparam -out prime256v1.pem -name prime256v1

# generate CA key and cert
${OPENSSL} req -x509 -new -newkey ec:prime256v1.pem -keyout ${CERT_DIR}/CA.key -out ${CERT_DIR}/CA.crt -nodes -subj "/CN=OQS test ecdsap256 CA" -days 365

# generate server CSR
${OPENSSL} req -new -newkey ec:prime256v1.pem -keyout ${CERT_DIR}/server.key -out ${CERT_DIR}/server.csr -nodes -subj "/CN=oqstest CA ecdsap256"

# generate server cert
${OPENSSL} x509 -req -in ${CERT_DIR}/server.csr -out ${CERT_DIR}/server.crt -CA ${CERT_DIR}/CA.crt -CAkey ${CERT_DIR}/CA.key -CAcreateserial -days 365

function cleanup() {
    ##########################
    # Remove files
    ##########################
    rm -f prime256v1.pem \
          s_timer.o

    ##########################
    # Remove network namespaces
    ##########################
    sudo ip netns del cli_ns
    sudo ip netns del srv_ns
}
trap cleanup INT KILL TERM EXIT

##########################
# Start S2N Server
##########################
sudo ip netns exec srv_ns ${S2ND} -c "PQ-TLS-1-3-2023-06-01" 10.0.0.1 4433
