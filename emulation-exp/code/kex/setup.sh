#!/bin/bash
set -ex

ROOT="$(dirname $(pwd))"

OPENSSL=${ROOT}/tmp/openssl/apps/openssl
OPENSSL_CNF=${ROOT}/tmp/openssl/apps/openssl.cnf

NGINX_CONF_DIR=${ROOT}/tmp/nginx/conf
S2ND=${ROOT}/tmp/s2n-tls/build/bin/s2nd

##########################
# Build s_timer
##########################
make s_timer.o

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
${OPENSSL} req -x509 -new -newkey ec:prime256v1.pem -keyout ${NGINX_CONF_DIR}/CA.key -out ${NGINX_CONF_DIR}/CA.crt -nodes -subj "/CN=OQS test ecdsap256 CA" -days 365 -config ${OPENSSL_CNF}

# generate server CSR
${OPENSSL} req -new -newkey ec:prime256v1.pem -keyout ${NGINX_CONF_DIR}/server.key -out ${NGINX_CONF_DIR}/server.csr -nodes -subj "/CN=oqstest CA ecdsap256" -config ${OPENSSL_CNF}

# generate server cert
${OPENSSL} x509 -req -in ${NGINX_CONF_DIR}/server.csr -out ${NGINX_CONF_DIR}/server.crt -CA ${NGINX_CONF_DIR}/CA.crt -CAkey ${NGINX_CONF_DIR}/CA.key -CAcreateserial -days 365

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
trap cleanup INT TERM

##########################
# Start nginx
##########################
sudo ip netns exec srv_ns ${S2ND} 10.0.0.1 4433 || /bin/true

cleanup
