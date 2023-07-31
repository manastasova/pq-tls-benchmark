#!/bin/bash
set -ex
set -o pipefail

# Default ubunt docker image already runs as root but doesn't have sudo installed
which sudo || ( apt update && apt install sudo )

sudo apt update
sudo apt install -y git \
               build-essential \
               autoconf \
               automake \
               libtool \
               ninja-build \
               libssl-dev \
               libpcre3-dev \
               golang-go \
               wget

NGINX_VERSION=1.17.5
CMAKE_VERSION=3.18
CMAKE_BUILD=3

TMP=$(mktemp -d)
rm -rf ${TMP}
mkdir -p ${TMP}
cd ${TMP}
ROOT=${TMP}
INSATLL_DIR=${ROOT}/install
rm -rf ${INSATLL_DIR}
mkdir -p ${INSATLL_DIR}

# Fetch all the files we need
wget https://cmake.org/files/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}.${CMAKE_BUILD}-Linux-x86_64.sh
wget nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && tar -zxvf nginx-${NGINX_VERSION}.tar.gz
git clone --single-branch --branch pq-tls-experiment https://github.com/xvzcf/liboqs
git clone --single-branch --branch pq-tls-experiment https://github.com/xvzcf/openssl
git clone --single-branch --branch main https://github.com/WillChilds-Klein/s2n-tls
git clone --single-branch --branch main https://github.com/WillChilds-Klein/aws-lc

# Install the latest CMake
mkdir cmake
sh cmake-${CMAKE_VERSION}.${CMAKE_BUILD}-Linux-x86_64.sh --skip-license --prefix=${ROOT}/cmake
CMAKE=${ROOT}/cmake/bin/cmake

# build liboqs
pushd liboqs
rm -rf build
mkdir build
pushd build
${CMAKE} \
    -GNinja \
    -DCMAKE_INSTALL_PREFIX=${ROOT}/openssl/oqs \
    ..
ninja && ninja install
popd    # build
popd    # liboqs

# build nginx (which builds OQS-OpenSSL)
pushd nginx-${NGINX_VERSION}
./configure --prefix=${ROOT}/nginx \
                --with-debug \
                --with-http_ssl_module --with-openssl=${ROOT}/openssl \
                --without-http_gzip_module \
                --with-cc-opt="-I ${ROOT}/openssl/oqs/include" \
                --with-ld-opt="-L ${ROOT}/openssl/oqs/lib";
sed -i 's/libcrypto.a/libcrypto.a -loqs/g' objs/Makefile;
sed -i 's/EVP_MD_CTX_create/EVP_MD_CTX_new/g; s/EVP_MD_CTX_destroy/EVP_MD_CTX_free/g' src/event/ngx_event_openssl.c;
make
make install
popd

# build AWS-LC
pushd aws-lc
rm -rf build
mkdir -p build
pushd build
${CMAKE} \
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
pushd s2n-tls
rm -rf build
mkdir -p build
pushd build
${CMAKE} \
    -DCMAKE_PREFIX_PATH=${INSATLL_DIR} \
    -DCMAKE_INSTALL_PREFIX=${INSATLL_DIR} \
    -DCMAKE_VERBOSE_MAKEFILE=1 \
    ..
make -j $(nproc) 2>&1
make install -j $(nproc)
popd    # build
popd    # s2n-tls
