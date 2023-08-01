# Build and run with:
#
# docker build -t pq-bench . && docker run -it -v $(pwd):/pq-bench pq-bench /bin/bash

FROM public.ecr.aws/ubuntu/ubuntu:22.04_stable

RUN mkdir /pq-bench
COPY . /pq-bench
WORKDIR /pq-bench

RUN apt update -y
RUN apt install -y \
               git \
               autoconf \
               automake \
               build-essential \
               cmake=3.22.1-1ubuntu1.22.04.1 \
               curl \
               golang-go \
               libtool \
               libpcre3-dev \
               ninja-build=1.10.1-1 \
               openssl=3.0.2-0ubuntu1.10 \
               python3=3.10.6-1~22.04 \
               sudo

RUN ./install-prereqs-ubuntu.sh
WORKDIR /pq-bench/kex
RUN make s_timer.o

ENTRYPOINT ./setup.sh
