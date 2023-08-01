#!/bin/bash
set -ex
set -o pipefail

# AWS-LC requires golang modules, module proxy is blocked on some networks
export GOPROXY=direct

ROOT=$(pwd)
INSATLL_DIR=${ROOT}/install
rm -rf ${INSTALL_DIR}
mkdir -p ${INSATLL_DIR}

# build AWS-LC
git clone --single-branch --branch main https://github.com/WillChilds-Klein/aws-lc
pushd aws-lc
rm -rf build
mkdir -p build
pushd build
cmake \
    -DFIPS=1 \
    -DCMAKE_PREFIX_PATH=${INSATLL_DIR} \
    -DCMAKE_INSTALL_PREFIX=${INSATLL_DIR} \
    -DCMAKE_VERBOSE_MAKEFILE=1 \
    -DENABLE_DILITHIUM=ON \
    ..
make -j $(nproc) 2>&1
make install -j $(nproc)
popd    # build
popd    # aws-lc

# build s2n
git clone --single-branch --branch main https://github.com/WillChilds-Klein/s2n-tls
pushd s2n-tls
rm -rf build
mkdir -p build
pushd build
cmake \
    -DCMAKE_PREFIX_PATH=${INSATLL_DIR} \
    -DCMAKE_INSTALL_PREFIX=${INSATLL_DIR} \
    -DCMAKE_VERBOSE_MAKEFILE=1 \
    ..
make -j $(nproc) 2>&1
make install -j $(nproc)
popd    # build
popd    # s2n-tls
