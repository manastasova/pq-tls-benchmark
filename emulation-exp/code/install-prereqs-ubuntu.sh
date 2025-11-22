#!/bin/bash
set -ex
set -o pipefail

# AWS-LC requires golang modules, module proxy is blocked on some networks
export GOPROXY=direct

ROOT=$(pwd)
INSTALL_DIR=${ROOT}/install
rm -rf ${INSTALL_DIR}
mkdir -p ${INSTALL_DIR}

# build AWS-LC
[[ -d aws-lc ]] || git clone https://github.com/aws/aws-lc
pushd aws-lc
rm -rf build
mkdir -p build
pushd build
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} \
    ../aws-lc
ninja
ninja install
popd    # build
popd    # aws-lc

# build s2n
[[ -d s2n-tls ]] || git clone https://github.com/aws/s2n-tls
pushd s2n-tls
rm -rf build
mkdir -p build
cd build
cmake . -Bbuild \
    -DCMAKE_PREFIX_PATH=${INSTALL_DIR} \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="-DS2N_LIBCRYPTO_SUPPORTS_MLDSA=1" \
    -DS2N_LIBCRYPTO_SUPPORTS_MLDSA=1 \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} ../
cmake --build build -j $(nproc)
cmake --install build
popd    # build
popd    # s2n-tls
